import argparse
import asyncio
import base64
import configparser
import locale
import logging
import os
import traceback
from collections import deque

import aiohttp
import aioprocessing
import mass_api_client as mac
import requests
from OpenSSL import crypto
from mass_api_client.resources import *
from mass_api_client.utils import get_or_create_analysis_system_instance

import certlib

try:
    locale.setlocale(locale.LC_ALL, 'en_US.utf8')
except locale.Error:
    print('LOCALE FAIL')
    pass

DOWNLOAD_QUEUE_SIZE = 24
MASS_QUEUE_SIZE = 24


async def mass_worker(parse_results_queue, mass_concurrency):
    process_pool = aioprocessing.AioPool()
    await process_pool.coro_map(mass, [parse_results_queue for _ in range(mass_concurrency)])
    process_pool.close()
    await process_pool.coro_join()


def mass(queue):
    anal_system_instance = get_or_create_analysis_system_instance(identifier='crawl',
                                                                  verbose_name='crawl',
                                                                  tag_filter_exp='sample-type:domainsample',
                                                                  )
    while True:
        entries = queue.get()
        if entries is None:
            break
        print('[{}] Submitting {} Samples to MASS...'.format(os.getpid(), len(entries)))
        for entry in entries:
            for i in range(3):
                try:
                    s = Sample.create(domain=entry['all_domains'][0])
                    scheduled = anal_system_instance.schedule_analysis(s)
                    scheduled.create_report(
                        json_report_objects={'domain_report': ('domain_report', entry)},
                    )
                    break
                except requests.HTTPError:
                    if i == 2:
                        logging.error('HTTPError while creating a sample.')


async def download_worker(session, log_info, work_deque, download_queue, timestamp):
    while True:
        try:
            start, end = work_deque.popleft()
        except IndexError:
            return

        for x in range(5):
            try:
                async with session.get(certlib.DOWNLOAD.format(log_info['url'], start, end)) as response:
                    entry_list = await response.json()
                    break
            except Exception as e:
                if x == 4:
                    logging.error("Exception getting block {}-{}! {}".format(start, end, e))
        else:  # Notorious for else, if we didn't encounter a break our request failed 3 times D:
            with open('/tmp/fails.csv', 'a') as f:
                f.write(",".join([log_info['url'], str(start), str(end)]))
            return

        for index, entry in zip(range(start, end + 1), entry_list['entries']):
            entry['cert_index'] = index
        await download_queue.put(({"entries": entry_list['entries'],
                                   "log_info": log_info,
                                   "start": start,
                                   "end": end
                                   }, timestamp))


async def retrieve_certificates(loop, urls, download_concurrency, mass_concurrency, timestamp=0):
    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        ctl_logs = await certlib.retrieve_all_ctls(session)
        for log in ctl_logs:
            if log['url'] not in urls:
                continue
            work_deque = deque()
            download_results_queue = asyncio.Queue(maxsize=DOWNLOAD_QUEUE_SIZE)
            manager = aioprocessing.AioManager()
            parse_results_queue = manager.Queue(maxsize=MASS_QUEUE_SIZE)

            logging.info("Downloading certificates for {}".format(log['description']))
            try:
                log_info = await certlib.retrieve_log_info(log, session)
            except (aiohttp.ClientConnectorError, aiohttp.ServerTimeoutError, aiohttp.ClientOSError,
                    aiohttp.ClientResponseError) as e:
                logging.error("Failed to connect to CTL! -> {} - skipping.".format(e))
                continue

            try:
                await certlib.populate_work(work_deque, log_info, start=0)
            except Exception as e:
                logging.error("Log needs no update - {}".format(e))
                continue
            download_tasks = asyncio.gather(*[
                download_worker(session, log_info, work_deque, download_results_queue, timestamp)
                for _ in range(download_concurrency)
            ])
            processing_task = asyncio.ensure_future(processing_coro(download_results_queue, parse_results_queue))
            asyncio.ensure_future(download_tasks)

            mass_task = asyncio.ensure_future(mass_worker(parse_results_queue, mass_concurrency))

            await download_tasks
            await download_results_queue.put(None)  # Downloads are done, processing can stop
            await processing_task
            for _ in range(0, mass_concurrency):
                parse_results_queue.put(None)
                print('putted')
            print('Parsing complete. MASS Queue: {}'.format(parse_results_queue.qsize() - mass_concurrency))
            await mass_task

            logging.info('Completed.')


async def processing_coro(download_results_queue, parse_result_queue):
    logging.info("Starting processing coro and process pool")
    process_pool = aioprocessing.AioPool()

    done = False

    while True:
        entries_iter = []
        logging.info("Getting things to process...")
        for _ in range(int(process_pool.pool_workers)):
            entries = await download_results_queue.get()
            if entries is not None:
                entries_iter.append(entries)
            else:
                done = True
                break

        if len(entries_iter) > 0:
            results = await process_pool.coro_map(process_worker, entries_iter)
            for result in results:
                if len(result) > 0:
                    print('KDFJLSKJFKLDSJFLKSJDLFJLSDSDF')
                    parse_result_queue.put(result)

        if done:
            break

    process_pool.close()

    await process_pool.coro_join()


def process_worker(arg):
    result_info = arg[0]
    timestamp = arg[1]
    parsed_results = []

    if not result_info:
        return
    try:
        print("[{}] Parsing...".format(os.getpid()))
        for entry in result_info['entries']:
            mtl = certlib.MerkleTreeHeader.parse(base64.b64decode(entry['leaf_input']))

            if mtl.Timestamp / 1000 < timestamp:
                continue

            cert_data = {}
            if mtl.LogEntryType == "X509LogEntryType":
                cert_data['type'] = "X509LogEntry"
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, certlib.Certificate.parse(mtl.Entry).CertData)]
                extra_data = certlib.CertificateChain.parse(base64.b64decode(entry['extra_data']))
                for cert in extra_data.Chain:
                    chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData))
            else:
                cert_data['type'] = "PreCertEntry"
                extra_data = certlib.PreCertEntry.parse(base64.b64decode(entry['extra_data']))
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]

                for cert in extra_data.Chain:
                    chain.append(
                        crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)
                    )
            cert_data.update({
                "leaf_cert": certlib.dump_cert(chain[0]),
                "chain": [certlib.dump_cert(x) for x in chain[1:]]
            })
            certlib.add_all_domains(cert_data)

            cert_data['source'] = {
                "url": result_info['log_info']['url'],
            }

            parsed_results.append({'log_url': result_info['log_info']['url'],
                                   'all_domains': cert_data['leaf_cert']['all_domains'],
                                   'not_before': str(cert_data['leaf_cert']['not_before']),
                                   'not_after': str(cert_data['leaf_cert']['not_after']),
                                   'sct_timestamp': mtl.Timestamp / 1000})
    except Exception as e:
        print("========= EXCEPTION =========")
        traceback.print_exc()
        print(e)
        print("=============================")

    return parsed_results


def main():
    config = configparser.ConfigParser()
    config.read('config.ini')
    ctl_urls = config.get('General', 'CT Logs')
    mass_concurrency = config.get('General', 'MASS concurrency')
    download_concurrency = config.get('General', 'download concurrency')
    timestamp_filter = config.get('General', 'filter')

    loop = asyncio.get_event_loop()

    parser = argparse.ArgumentParser(description='Pull down certificate transparency list information')

    parser.add_argument('-u', dest="ctl_urls", action="store", default=ctl_urls, help="Retrieve this CTLs")

    parser.add_argument('-c', dest='download_concurrency', action='store', default=download_concurrency, type=int,
                        help="The number of concurrent downloads to run at a time")

    parser.add_argument('-m', dest='mass_concurrency', action='store', default=mass_concurrency, type=int,
                        help="The number of concurrent downloads to run at a time")

    parser.add_argument('-f', dest='timestamp_filter', action='store', default=timestamp_filter, type=int,
                        help="Certificates with a SCT older than this value are ignored.")

    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

    logging.info("Starting...")
    mac.ConnectionManager().register_connection('default', config.get('General', 'MASS api key'),
                                                config.get('General', 'MASS server address'))

    loop.run_until_complete(
        retrieve_certificates(loop, download_concurrency=args.download_concurrency, timestamp=args.timestamp_filter,
                              urls=args.ctl_urls.replace(' ', '').split(','),
                              mass_concurrency=args.mass_concurrency))


if __name__ == "__main__":
    main()

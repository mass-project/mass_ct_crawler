import argparse
import asyncio
import base64
import configparser
import locale
import logging
import os
import time
import traceback
from collections import deque

import aiohttp
import aioprocessing
# from ct_crawler import certlib
import certlib
import mass_api_client as mac
import requests
from OpenSSL import crypto
from mass_api_client.resources import *
from mass_api_client.utils import get_or_create_analysis_system_instance

try:
    locale.setlocale(locale.LC_ALL, 'en_US.utf8')
except locale.Error:
    print('LOCALE FAIL')
    pass

DOWNLOAD_QUEUE_SIZE = 40
MASS_QUEUE_SIZE = 24


async def mass_worker(parse_results_queue, mass_concurrency):
    process_pool = aioprocessing.AioPool()
    await process_pool.coro_map(mass, [parse_results_queue for _ in range(mass_concurrency)])
    process_pool.close()
    await process_pool.coro_join()


def mass(queue):
    anal_system_instance = get_or_create_analysis_system_instance(identifier='crawl',
                                                                  verbose_name='ct_crawler',
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
                    s = Sample.create(domain=entry['all_domains'][0], tags=['domain_with_cert'])
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
                logging.info('Getting block {}-{}'.format(start, end))
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


async def retrieve_certificates(loop, download_concurrency, mass_concurrency, time_sec, once, anal_system_instance):
    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        while True:
            urls = get_ctls_from_mass(anal_system_instance)
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
                    download_worker(session, log_info, work_deque, download_results_queue, urls[log['url']])
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
                print('Parsing complete. MASS Queue: {}'.format(parse_results_queue.qsize()))
                await mass_task
            if not once:
                logging.info('Completed. Sleeping for {} seconds.'.format(time_sec))
                time.sleep(time_sec)
            else:
                logging.info('Completed.')
                break


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
            if cert_data['leaf_cert']['not_before'] < timestamp:
                continue
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


def submit_ctls_to_mass(urls, timestamp, anal_system_instance):
    logging.info("Submitting following CTLogs to MASS: {}".format(urls))
    for url in urls:
        for i in range(3):
            try:
                s = Sample.create(domain=url, tags=['ctlog'])
                scheduled = anal_system_instance.schedule_analysis(s)
                scheduled.create_report(
                    json_report_objects={'ctl_report': ('ctl_report', {'time': timestamp})},
                )
                break
            except requests.HTTPError:
                if i == 2:
                    logging.error('HTTPError while creating a CTL sample.')


def get_ctls_from_mass(anal_system_instance):
    new_time = time.time()
    dict = {}
    # TODO: BUG??? ctls = Sample.query(tags__all='ctlog')
    ctls = Sample.query()
    for ctl in ctls:
        if 'ctlog' in ctl.tags:
            # assumption: report[0] is the latest report
            report = ctl.get_reports()[0]
            dict[ctl.unique_features.domain] = report.json_reports['ctl_report']['time']
            scheduled = anal_system_instance.schedule_analysis(ctl)
            scheduled.create_report(
                json_report_objects={'ctl_report': ('ctl_report', {'time': new_time})},
            )
    return dict


def main():
    config = configparser.ConfigParser()
    config.read('config.ini')
    ctl_urls = config.get('General', 'CT Logs')
    mass_concurrency = config.get('General', 'MASS concurrency')
    download_concurrency = config.get('General', 'download concurrency')
    start_timestamp = config.get('General', 'start timestamp')
    crawl_once = config.getboolean('General', 'crawl once')
    time_sleep = config.get('General', 'time sleep')
    add_urls = config.getboolean('General', 'add CT Logs')

    loop = asyncio.get_event_loop()

    parser = argparse.ArgumentParser(description='Pull down certificate transparency list information')

    parser.add_argument('-u', dest="ctl_urls", action="store_true", default=add_urls,
                        help="Retrieve the CTLs defined in config.ini additionally to CTLs stored in MASS")

    parser.add_argument('-c', dest='download_concurrency', action='store', default=download_concurrency, type=int,
                        help="The number of concurrent downloads to run at a time")

    parser.add_argument('-m', dest='mass_concurrency', action='store', default=mass_concurrency, type=int,
                        help="The number of concurrent MASS submitter to run at a time")

    parser.add_argument('-f', dest='start_timestamp', action='store', default=start_timestamp, type=int,
                        help="Certificates with a SCT older than this value are ignored.")

    parser.add_argument('-o', dest='crawl_once', action='store_true', default=crawl_once,
                        help='Crawl only once.')

    parser.add_argument('-t', dest='time_sleep', action='store', default=time_sleep, type=int,
                        help='If crawl once with -o is NOT chosen this sets the time too sleep between crawls.')

    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

    logging.info("Starting...")
    mac.ConnectionManager().register_connection('default', config.get('General', 'MASS api key'),
                                                config.get('General', 'MASS server address'))

    anal_system_instance = get_or_create_analysis_system_instance(identifier='crawl',
                                                                  verbose_name='ct_crawler',
                                                                  tag_filter_exp='sample-type:domainsample',
                                                                  )

    if args.ctl_urls:
        submit_ctls_to_mass(ctl_urls.replace(' ', '').split(','), args.start_timestamp, anal_system_instance)

    loop.run_until_complete(
        retrieve_certificates(loop, download_concurrency=args.download_concurrency, anal_system_instance=anal_system_instance,
                              mass_concurrency=args.mass_concurrency, time_sec=args.time_sleep, once=args.crawl_once))


if __name__ == "__main__":
    main()

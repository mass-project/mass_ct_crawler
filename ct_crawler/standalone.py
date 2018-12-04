import argparse
import asyncio
import base64
import configparser
import locale
import logging
import os
import signal
import sys
import time
import traceback
from collections import deque

import aiohttp
import aioprocessing
# from ct_crawler import certlib
import certlib
from OpenSSL import crypto

try:
    locale.setlocale(locale.LC_ALL, 'en_US.utf8')
except locale.Error:
    logging.error('LOCALE FAIL')
    pass

anal_system_instance = None
DOWNLOAD_QUEUE_SIZE = 40
MASS_QUEUE_SIZE = 1000
DOWNLOAD_TRIES = 30


def sigterm_handler(signal, frame):
    anal_system_instance.delete()
    logging.info('exit')
    sys.exit(0)


signal.signal(signal.SIGTERM, sigterm_handler)


async def mass_worker(parse_results_queue, mass_concurrency, interval):
    return
    logging.info("Starting worker...")
    process_pool = aioprocessing.AioPool(mass_concurrency)
    await process_pool.coro_starmap(mass, [(parse_results_queue, interval)])
    process_pool.close()
    await process_pool.coro_join()


def mass(queue):
    logging.info("Reading from queue...")
    with open('results.txt', 'w') as fp:
        fp.write("# Domains")
        fp.flush()
        while True:
            entry = queue.get()
            if entry is None:
                break

            for domain in entry['all_domains']:
                fp.write(domain)
                fp.write('\n')


async def download_worker(session, log_info, work_deque, download_queue, report):
    while True:
        try:
            start, end = work_deque.popleft()
        except IndexError:
            return

        for x in range(DOWNLOAD_TRIES):
            try:
                logging.info('Getting block {}-{}'.format(start, end))
                async with session.get(certlib.DOWNLOAD.format(log_info['url'], start, end)) as response:
                    entry_list = await response.json()
                    break
            except Exception as e:
                if x == DOWNLOAD_TRIES - 1:
                    logging.error("Exception getting block {}-{}! {}".format(start, end, e))
        else:
            return

        for index, entry in zip(range(start, end + 1), entry_list['entries']):
            entry['cert_index'] = index
        await download_queue.put(({"entries": entry_list['entries'],
                                   "log_info": log_info,
                                   "start": start,
                                   "end": end
                                   }, report))


async def find_timestamp(loop, ctl, timestamp):
    best_data = None
    log_info = None
    chunks = None
    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        ctl_logs = await certlib.retrieve_all_ctls(session)
        for log in ctl_logs:
            if log['url'] != ctl:
                continue
            log_info = await certlib.retrieve_log_info(log, session)
            chunks = int((log_info['tree_size'] - 1) / log_info['block_size'])

        lo, hi = 0, chunks * log_info['block_size']
        best_ind = lo
        data_best_ind = await certlib.get_mean(session, log_info['url'], lo, log_info['block_size'])

        while lo <= hi:
            mid = int(round(lo + (hi - lo) / 2))
            data_mid = int(await certlib.get_mean(session, log_info['url'], mid, log_info['block_size']))
            if data_mid < timestamp:
                lo = mid + log_info['block_size']
            elif data_mid > timestamp:
                hi = mid - log_info['block_size']
            else:
                best_ind = mid
                best_data = data_mid
                break
            if abs(data_mid - timestamp) <= abs(data_best_ind - timestamp):
                best_ind = mid
                best_data = data_mid
        logging.info('Searched For Timestamp: {}. Found: {}'.format(timestamp, best_data))
        return best_ind


async def retrieve_certificates(loop, download_concurrency, mass_concurrency, ctl, time_sec=60, once=1, interval=False,
                                start=None, end=None, desired_start=None):
    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        while True:
            pre = time.time()
            ctl_logs = await certlib.retrieve_all_ctls(session)
            for log in ctl_logs:
                if log['url'] != ctl:
                    continue

                """log_data = get_ctl_from_mass(log['url'])
                if log_data is None:
                    logging.error('No CTL entry found in database.')
                    break"""
                log_data = None

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
                    await certlib.populate_work(work_deque, log_info, start=start, limit=end)
                except Exception as e:
                    logging.info("Log needs no update - {}".format(e))
                    continue

                download_tasks = asyncio.gather(*[
                    download_worker(session, log_info, work_deque, download_results_queue, log_data)
                    for _ in range(download_concurrency)
                ])
                processing_task = asyncio.ensure_future(processing_coro(download_results_queue, parse_results_queue))
                asyncio.ensure_future(download_tasks)

                mass_task = asyncio.ensure_future(mass_worker(parse_results_queue, mass_concurrency, desired_start))

                await download_tasks
                await download_results_queue.put(None)  # Downloads are done, processing can stop
                await processing_task
                for _ in range(0, mass_concurrency):
                    parse_results_queue.put(None)
                logging.info('Parsing complete. MASS Queue: {}'.format(parse_results_queue.qsize()))
                await mass_task

            if once == 0:
                after = time.time()
                new = time_sec - (after - pre)
                logging.info('Completed. Sleeping for {} seconds.'.format(int(new)))
                if new > 0:
                    time.sleep(new)
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
                    logging.info('[{}] Adding {} Samples to file...'.format(os.getpid(), len(result)))
                    with open('results.txt', 'a') as fp:
                        for res in result:
                            for domain in res['all_domains']:
                                fp.write(domain)
                                fp.write('\n')
                        print("[{}] Writing to file finished.".format(os.getpid()))

        if done:
            break

    process_pool.close()

    await process_pool.coro_join()


def process_worker(arg):
    result_info = arg[0]
    parsed_results = []

    if not result_info:
        return
    try:
        logging.info("[{}] Parsing...".format(os.getpid()))
        for entry in result_info['entries']:
            mtl = certlib.MerkleTreeHeader.parse(base64.b64decode(entry['leaf_input']))
            cert_data = {}
            if mtl.LogEntryType == "X509LogEntryType":
                cert_data['type'] = "X509LogEntry"
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, certlib.Certificate.parse(mtl.Entry).CertData)]
            else:
                cert_data['type'] = "PreCertEntry"
                extra_data = certlib.PreCertEntry.parse(base64.b64decode(entry['extra_data']))
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]
            cert_data.update({
                "leaf_cert": certlib.dump_cert(chain[0]),
                "chain": [certlib.dump_cert(x) for x in chain[1:]]
            })
            certlib.add_all_domains(cert_data)

            cert_data['source'] = {
                "url": result_info['log_info']['url'],
            }
            for domain in cert_data['leaf_cert']['all_domains']:
                if '.' in domain:
                    break
            else:
                continue

            output = {'log_url': result_info['log_info']['url'],
                      'all_domains': cert_data['leaf_cert']['all_domains'],
                      'not_before': cert_data['leaf_cert']['not_before'],
                      'not_after': cert_data['leaf_cert']['not_after'],
                      'sct_timestamp': mtl.Timestamp / 1000}
            if cert_data['leaf_cert']['all_domains'][0].startswith('*.'):
                output['wildcard'] = 'wildcard_true'
            else:
                output['wildcard'] = 'wildcard:false'

            parsed_results.append(output)
    except Exception as e:
        print("========= EXCEPTION =========")
        traceback.print_exc()
        print(e)
        print("=============================")

    return parsed_results


def main():
    global anal_system_instance
    config = configparser.ConfigParser()
    config.read('config.ini')
    ct_logs = os.environ.get('CT_LOGS', config.get('General', 'CT Logs'))
    download_concurrency = 1
    time_sleep = int(os.environ.get('TIME_SLEEP', config.get('General', 'time sleep')))
    add_urls = int(os.environ.get('ADD_URLS', config.get('General', 'add CT Log')))
    fix_interval = int(os.getenv('MASS_FIX_INTERVAL', config.get('General', 'Fix Interval')))
    timestamp_start = int(os.getenv('MASS_START', config.get('General', 'timestamp start')))
    timestamp_end = int(os.getenv('MASS_END', config.get('General', 'timestamp end')))

    loop = asyncio.get_event_loop()

    parser = argparse.ArgumentParser(description='Pull down certificate transparency list and store it in MASS.')

    parser.add_argument('-u', dest="add_urls", action="store", default=add_urls, type=int,
                        help="Retrieve the CTLs defined in config.ini additionally to CTLs stored in MASS")

    parser.add_argument('-c', dest='download_concurrency', action='store', default=download_concurrency, type=int,
                        help="The number of concurrent downloads to run at a time")

    parser.add_argument('-t', dest='time_sleep', action='store', default=time_sleep, type=int,
                        help='If crawl once with -o is NOT chosen this sets the time to sleep between crawls.')

    parser.add_argument('-fi', dest='fix_interval', action='store', default=fix_interval, type=int,
                        help='If crawl once with -o is NOT chosen this sets the time to sleep between crawls.')

    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

    logging.info("Starting...")
    logging.info('Searching for Interval...')

    tasks = find_timestamp(loop, ctl=ct_logs, timestamp=timestamp_start), \
            find_timestamp(loop, ctl=ct_logs, timestamp=timestamp_end)
    start, end = loop.run_until_complete(asyncio.gather(*tasks))
    logging.info("Interval found: {}-{}".format(start, end))
    loop.run_until_complete(
        retrieve_certificates(loop, download_concurrency=args.download_concurrency,
                              mass_concurrency=1,
                              ctl=ct_logs,
                              interval=True,
                              start=start,
                              end=end,
                              desired_start=timestamp_start))


if __name__ == "__main__":
    main()

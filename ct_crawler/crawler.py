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
import certlib
import mass_api_client as mac
import requests
from OpenSSL import crypto
from mass_api_client.resources import *
from mass_api_client.utils import get_or_create_analysis_system
from mass_api_client.utils.multistaged_analysis import AnalysisFrame, CreateSampleAndReportObject
from mass_api_client.utils.multistaged_analysis.miscellaneous import create_sample

# from ct_crawler import certlib

try:
    locale.setlocale(locale.LC_ALL, 'en_US.utf8')
except locale.Error:
    logging.error('LOCALE FAIL')
    pass

DOWNLOAD_QUEUE_SIZE = 40
DOWNLOAD_TRIES = 30


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


async def retrieve_certificates(loop, sockets, download_concurrency, ctl,
                                time_sec=60, once=1,
                                interval=False,
                                start=None, end=None):
    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        while True:
            pre = time.time()
            ctl_logs = await certlib.retrieve_all_ctls(session)
            for log in ctl_logs:
                if log['url'] != ctl:
                    continue

                log_data = get_ctl_from_mass(log['url'])
                if log_data is None:
                    logging.error('No CTL entry found in database.')
                    break

                work_deque = deque()
                download_results_queue = asyncio.Queue(maxsize=DOWNLOAD_QUEUE_SIZE)

                logging.info("Downloading certificates for {}".format(log['description']))
                try:
                    log_info = await certlib.retrieve_log_info(log, session)
                except (aiohttp.ClientConnectorError, aiohttp.ServerTimeoutError, aiohttp.ClientOSError,
                        aiohttp.ClientResponseError) as e:
                    logging.error("Failed to connect to CTL! -> {} - skipping.".format(e))
                    continue

                if not interval:
                    if log_data['initial'] is True:
                        log_data['offset'] = log_info['tree_size'] - log_data['offset']

                if not interval:
                    try:
                        await certlib.populate_work(work_deque, log_info, start=log_data['offset'],
                                                    limit=log_info['tree_size'])
                    except Exception as e:
                        logging.info("Log needs no update - {}".format(e))
                        continue
                else:
                    try:
                        await certlib.populate_work(work_deque, log_info, start=start, limit=end)
                    except Exception as e:
                        logging.info("Log needs no update - {}".format(e))
                        continue

                download_tasks = asyncio.gather(*[
                    download_worker(session, log_info, work_deque, download_results_queue, log_data)
                    for _ in range(download_concurrency)
                ])
                processing_task = asyncio.ensure_future(processing_coro(download_results_queue, interval, sockets))
                asyncio.ensure_future(download_tasks)

                await download_tasks
                await download_results_queue.put(None)  # Downloads are done, processing can stop
                await processing_task

                if not interval:
                    create_ctl_report(log['url'], log_info['tree_size'], analysis_system)

            if once == 0:
                after = time.time()
                new = time_sec - (after - pre)
                logging.info('Completed. Sleeping for {} seconds.'.format(int(new)))
                if new > 0:
                    time.sleep(new)
            else:
                logging.info('Completed.')
                break


async def processing_coro(download_results_queue, interval, sockets):
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
                    logging.info('Adding {} Samples to MASS Queue...'.format(len(result)))
                    for res in result:
                        # parse_result_queue.put(res)
                        metadata = {'log_url': res['log_url'],
                                    'not_before': res['not_before'],
                                    'not_after': res['not_after'],
                                    'sct_timestamp': res['sct_timestamp']}
                        if interval is None:
                            tags = ['domain_with_certificate', res['log_url'], res['wildcard']]
                        else:
                            tags = ['domain_with_certificate', res['log_url'], res['wildcard'], 'interval',
                                    'interval:{}'.format(interval)]
                        data = CreateSampleAndReportObject(sample_domain=res['all_domains'][0],
                                                           sample_tags=tags,
                                                           report_additional_metadata=metadata,
                                                           report_json_report_objects={
                                                               'domain_report': res})
                        sockets.send(data)
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


def submit_ctl_to_mass(url, crawl_depth):
    s = Sample.create(domain=url, tags=['ctlog', url], use_queue=False)
    Report.create_without_request(s, analysis_system, json_report_objects={
                                           'ctl_report': {'initial': True, 'offset': crawl_depth}}, use_queue=False)


def get_ctl_from_mass(domain):
    initial = None
    offset = None
    while True:
        try:
            ctls = Sample.query(domain=domain)
            for ctl in ctls:
                reports = ctl.get_reports()
                for rep in reports:
                    initial = rep.json_reports['ctl_report']['initial']
                    offset = rep.json_reports['ctl_report']['offset']
                    break
                return {'initial': initial, 'offset': offset}
            return None
        except (requests.HTTPError, requests.ReadTimeout) as e:
            print("========= EXCEPTION =========")
            traceback.print_exc()
            print(e)
            print("=============================")


def create_ctl_report(domain, offset, analysis_system):
    new_time = time.time()
    ctls = Sample.query(domain=domain)
    while True:
        try:
            for ctl in ctls:
                for old_report in ctl.get_reports():
                    old = old_report.json_reports['ctl_report']['offset']
                    old_report.delete()
                    delta = offset - old
                    Report.create_without_request(ctl, analysis_system, json_report_objects={
                        'ctl_report': {'time': new_time, 'initial': False,
                                       'offset': offset, 'delta': delta}}, use_queue=False)
                    break
                return
        except requests.HTTPError as e:
            print("========= EXCEPTION =========")
            traceback.print_exc()
            print(e)
            print("=============================")


def crawler(sockets):
    config = configparser.ConfigParser()
    config.read('config.ini')
    ct_logs = os.environ.get('CT_LOGS', config.get('General', 'CT Logs'))
    download_concurrency = int(os.environ.get('DOWNLOAD_CONCURRENCY', config.get('General', 'download concurrency')))
    time_sleep = int(os.environ.get('TIME_SLEEP', config.get('General', 'time sleep')))
    add_urls = int(os.environ.get('ADD_URLS', config.get('General', 'add CT Log')))
    crawl_depth = int(os.environ.get('CRAWL_DEPTH', config.get('General', 'first crawl depth')))
    fix_interval = int(os.getenv('MASS_FIX_INTERVAL', config.get('General', 'Fix Interval')))
    timestamp_start = int(os.getenv('MASS_START', config.get('General', 'timestamp start')))
    timestamp_end = int(os.getenv('MASS_END', config.get('General', 'timestamp end')))
    mode = os.getenv('MASS_MODE', config.get('General', 'mode'))

    loop = asyncio.get_event_loop()

    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

    logging.info("Starting...")
    if mode == 'interval':
        logging.info('Searching for Interval...')
        tasks = find_timestamp(loop, ctl=ct_logs, timestamp=timestamp_start), \
                find_timestamp(loop, ctl=ct_logs, timestamp=timestamp_end)
        start, end = loop.run_until_complete(asyncio.gather(*tasks))
        logging.info("Interval found: {}-{}".format(start, end))
        loop.run_until_complete(
            retrieve_certificates(loop, sockets, download_concurrency=download_concurrency,
                                  ctl=ct_logs,
                                  interval=True,
                                  start=start,
                                  end=end))

    elif mode == 'fix_interval':
        logging.info('Searching for Fix-Interval...')
        start = loop.run_until_complete(find_timestamp(loop, ctl=ct_logs, timestamp=timestamp_start))
        logging.info("start found: {} fi".format(start))
        loop.run_until_complete(
            retrieve_certificates(loop, sockets, download_concurrency=download_concurrency,
                                  ctl=ct_logs,
                                  interval=True,
                                  start=start,
                                  end=start + fix_interval))

    elif mode == 'crawl':
        logging.info('Start crawling...')
        if add_urls == 1:
            logging.info('Adding new CTL to MASS...')
            submit_ctl_to_mass(ct_logs, crawl_depth)
        loop.run_until_complete(
            retrieve_certificates(loop, sockets, download_concurrency=download_concurrency,
                                  time_sec=time_sleep,
                                  once=0,
                                  ctl=ct_logs))

    elif mode == 'crawl_once':
        logging.info('Start crawling once...')
        if add_urls == 1:
            logging.info('Adding new CTL to MASS...')
            submit_ctl_to_mass(ct_logs, crawl_depth)
        loop.run_until_complete(
            retrieve_certificates(loop, sockets, download_concurrency=download_concurrency,
                                  once=1,
                                  ctl=ct_logs))


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('config.ini')
    api_key = os.getenv('MASS_API_KEY', config.get('General', 'MASS api key'))
    server_addr = os.environ.get('MASS_SERVER', config.get('General', 'MASS server address'))
    mass_timeout = int(os.environ.get('MASS_TIMEOUT', '60'))

    mac.ConnectionManager().register_connection('default', api_key, server_addr, timeout=mass_timeout)
    analysis_system = get_or_create_analysis_system(identifier='crawl',
                                                    verbose_name='ct_crawler',
                                                    tag_filter_exp='sample-type:domainsample',
                                                    )
    frame = AnalysisFrame()
    frame.add_stage(crawler, 'crawler', next_stage='create_sample_and_report')
    frame.add_stage(create_sample, 'create_sample_and_report', args=(analysis_system,))

    frame.start_all_stages()

import argparse
import asyncio
import configparser
import logging
import signal
import sys
import time
from time import gmtime, strftime

import aiohttp
import mass_api_client as mac
import requests
from mass_api_client.resources import *
from mass_api_client.utils import get_or_create_analysis_system_instance

from ct_crawler import certlib


async def count(loop, urls):
    result = {}

    def signal_handler(signal, frame):
        for ctl in result:
            for i in range(3):
                try:
                    s = Sample.create(domain=ctl)
                    scheduled = anal_system_instance.schedule_analysis(s)
                    scheduled.create_report(json_report_objects={'counter_report': ('counter_report', result[ctl])})
                    break
                except requests.HTTPError:
                    if i == 2:
                        logging.error('HTTPError while creating a sample.')
            print('Submitted {}', ctl)
        sys.exit(0)

    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        anal_system_instance = get_or_create_analysis_system_instance(identifier='counter',
                                                                      verbose_name='counter',
                                                                      tag_filter_exp='sample-type:domainsample',
                                                                      )
        signal.signal(signal.SIGINT, signal_handler)
        ctl_logs = await certlib.retrieve_all_ctls(session)
        while True:
            for log in ctl_logs:
                if log['url'] not in urls:
                    continue
                log_info = await certlib.retrieve_log_info(log, session)
                try:
                    result[log['url']][strftime("%Y-%m-%d %H:%M:%S", gmtime())] = log_info['tree_size']
                except KeyError:
                    result[log['url']] = {strftime("%Y-%m-%d %H:%M:%S", gmtime()): log_info['tree_size']}

            print('sleep for 10 min.')
            time.sleep(600)


def main():
    loop = asyncio.get_event_loop()
    config = configparser.ConfigParser()
    config.read('config.ini')
    ctl_urls = config.get('Counter', 'CT Logs')
    parser = argparse.ArgumentParser(description='Pull down certificate transparency list information')

    parser.add_argument('-u', dest="ctl_urls", action="store", default=ctl_urls, help="Retrieve this CTLs")

    parser.add_argument('-c', dest='counter', action='store_true',
                        help="Certificates with a SCT older than this value are ignored.")
    parser.add_argument('-d', dest='directory', action='store',
                        help="Output directory.")
    args = parser.parse_args()

    mac.ConnectionManager().register_connection('default', config.get('Counter', 'MASS api key'),
                                                config.get('Counter', 'MASS server address'))

    if args.counter:
        loop.run_until_complete(count(loop, urls=args.ctl_urls.replace(' ', '').split(',')))


if __name__ == "__main__":
    main()

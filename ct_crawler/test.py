from mass_api_client.resources import *
from mass_api_client.utils import get_or_create_analysis_system_instance
import mass_api_client as mac
import os
import configparser
import requests
from multiprocessing import Pool

config = configparser.ConfigParser()
config.read('config.ini')

api_key = os.getenv('MASS_API_KEY', config.get('General', 'MASS api key'))
server_addr = os.environ.get('MASS_SERVER', config.get('General', 'MASS server address'))
mass_timeout = int(os.environ.get('MASS_TIMEOUT', '60'))

mac.ConnectionManager().register_connection('default', api_key, server_addr, timeout=mass_timeout)
anal_system_instance = get_or_create_analysis_system_instance(identifier='ct_crawler_test',
                                                                  verbose_name='ct_crawler_test',
                                                                  tag_filter_exp='sample-type:domainsample',
                                                                  )

def func(x):
    i = 0
    while True:
        try:
            metadata = {'log_url': 'xx',
                        'not_before': 'xx',
                        'not_after': 'xx',
                        'sct_timestamp': 'xx'}
            print('[{}] 1'.format(os.getpid()))
            s = Sample.create(domain='testdomain{}'.format(i),
                              tags=['crawler_test'])
            print('[{}] 2'.format(os.getpid()))
            scheduled = anal_system_instance.schedule_analysis(s)
            print('[{}] 3'.format(os.getpid()))
            scheduled.create_report(additional_metadata=metadata,
                                    json_report_objects={'domain_report': ('domain_report', 'test')},
                                    )
            print('[{}] 4'.format(os.getpid()))
            i += 1
        except requests.ConnectionError as e:
            print(e)


if __name__ == '__main__':
    x = 0
    with Pool() as p:
        p.map(func, [0,0,0,0,0,0,0,0])

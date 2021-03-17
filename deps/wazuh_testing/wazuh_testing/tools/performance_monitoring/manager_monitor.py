import argparse
import psutil
import logging
import os
import subprocess
import multiprocessing

from time import sleep
from datetime import datetime


"""
Script to monitor the following manager resources at the specified time:

- CPU USAGE
- MEM USAGE
- MEM USAGE PERCENT
- EVENTS EDPS
- EVENTS DROPPED
- REMOTED DISCARD COUNT
- REMOTED TCP SESSIONS

Displays data on screen and stores them in a CSV file.

(Makes sense to launch it when there are multiple agents reporting and you want to monitor the manager status).
"""

logger = logging.getLogger('manager_monitor')
logger.setLevel(logging.ERROR)
logger.addHandler(logging.StreamHandler())

CURRENT_WORKDIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA_FILE_PATH = os.path.join(CURRENT_WORKDIR, 'manager_monitor.csv')

STATE_FILES_PATH = os.path.join('/var', 'ossec', 'var', 'run')
ANALYSYSD_STATE = os.path.join(STATE_FILES_PATH, 'wazuh-analysisd.state')
REMOTED_STATE = os.path.join(STATE_FILES_PATH, 'wazuh-remoted.state')


def get_state_stat(file, stat):
    # It is necessary to use an auxiliary process to obtain the information because ansible captures all the output
    # and it is not possible to share this output between processes.
    subprocess.run(f"bash {CURRENT_WORKDIR}/get_stat.sh {file} {stat}", shell=True)

    aux_data_file = f"{CURRENT_WORKDIR}/tmp.txt"

    with open(aux_data_file) as stat_info:
        data = stat_info.read()

    data = data.split('=')[1].replace("'", '').replace('\n', '')

    os.remove(aux_data_file)

    return data


def write_headers(file):
    with open(file, 'w') as f:
        f.write('timestamp, cpu_usage, mem_usage, mem_percent, events_edps, events_dropped, remoted_discard_count, '
                'remoted_tcp_sessions\n')


def write_data(file, data):
    with open(file, 'a') as f:
        f.write(f"{datetime.now()}, {data[0]}, {data[1]}, {data[2]}, {data[3]}, {data[4]}, {data[5]}, {data[6]}\n")


def monitor(file, measurement_time):
    logger.info('Starting monitor...')

    while True:
        cpu_info = round(psutil.cpu_percent())
        memory_info = psutil.virtual_memory()
        memory_usage = round(memory_info.used / 1048576)
        memory_usage_percent = round(memory_info.percent)

        events_edps = get_state_stat(ANALYSYSD_STATE, 'events_edps')
        events_dropped = get_state_stat(ANALYSYSD_STATE, 'events_dropped')
        remoted_discard_count = get_state_stat(REMOTED_STATE, 'discarded_count')
        remoted_tcp_sessions = get_state_stat(REMOTED_STATE, 'tcp_sessions')

        data = (cpu_info, memory_usage, memory_usage_percent, events_edps, events_dropped, remoted_discard_count,
                remoted_tcp_sessions)

        logger.info(f"{datetime.now()} -- {cpu_info} -- {memory_usage} -- {memory_usage_percent} -- {events_edps}"
                    f" -- {events_dropped} -- {remoted_discard_count} -- {remoted_tcp_sessions}")

        write_data(file, data)

        sleep(measurement_time)

    logger.info('Stopping monitor...')


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t', metavar=('<monitoring_time>'),
                            type=int, required=True, help='Time in seconds for monitoring')
    arg_parser.add_argument('-m', metavar=('<measurement_time>'),
                            type=int, required=False, help='Time in seconds between measurement', default=10)
    arg_parser.add_argument('-f', metavar=('<file_path>'), default=DEFAULT_DATA_FILE_PATH,
                            type=str, required=False, help='File path where save results')
    arg_parser.add_argument('-v', action='store_true', required=False, help='Verbose prints')

    script_parameters = arg_parser.parse_args()

    monitoring_time = script_parameters.t
    measurement_time = script_parameters.m
    file = script_parameters.f
    verbose = script_parameters.v

    if verbose:
        logger.setLevel(logging.INFO)

    write_headers(file)

    proc = multiprocessing.Process(target=monitor, args=(file, measurement_time))

    # Wait to avoid CPU spike caused by launching this process
    sleep(1)

    proc.start()

    sleep(monitoring_time)

    proc.terminate()

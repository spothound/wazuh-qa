import argparse
import psutil
import multiprocessing
import logging
import os

from time import sleep
from datetime import datetime

"""
Script to monitor the use of CPU and memory resources by the machine where the simulated agents have been deployed.

Generates results both in output and in a CSV file.
"""

logger = logging.getLogger('agent_monitor')
logger.setLevel(logging.ERROR)
logger.addHandler(logging.StreamHandler())

DEFAULT_DATA_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent_monitor.csv')


def write_headers(file):
    with open(file, 'w') as f:
        f.write(f'timestamp, cpu_usage, mem_usage, mem_percent\n')


def write_data(file, data):
    with open(file, 'a') as f:
        f.write(f"{datetime.now()}, {data[0]}, {data[1]}, {data[2]}\n")


def monitor(file, measurement_time, verbose):
    logger.info('Starting monitor...')

    while True:
        cpu_info = round(psutil.cpu_percent())

        memory_info = psutil.virtual_memory()
        memory_usage = round(memory_info.used / 1048576)
        memory_usage_percent = round(memory_info.percent)

        logger.info(f"{datetime.now()} -- {cpu_info} -- {memory_usage} -- {memory_usage_percent}")

        write_data(file, (cpu_info, memory_usage, memory_usage_percent))

        sleep(measurement_time)

    logger.info('Stopping monitor...')


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t', metavar=('<monitoring_time>'),
                            type=int, required=True, help='Time in seconds for monitoring')
    arg_parser.add_argument('-m', metavar=('<measurement_time>'),
                            type=int, required=False, help='Time in seconds between measurements', default=10)
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

    proc = multiprocessing.Process(target=monitor, args=(file, measurement_time, verbose))

    # Wait to avoid CPU spike caused by launching this process
    sleep(1)

    proc.start()

    sleep(monitoring_time)

    proc.terminate()

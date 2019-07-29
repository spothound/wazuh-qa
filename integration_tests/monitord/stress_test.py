#!/usr/bin/env python
# July 25, 2019

import os, time, argparse, subprocess
import xml.etree.ElementTree as ET

def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', action='store', dest='time',
                        help='Time to execute the stress test [s]' , type=int)

    parser.add_argument('-r', action='store', dest='rotate',
                        help='Maximum number of permitted rotations in folder' , type=int)

    parser.add_argument('-c', action='store', dest='compress',
                        help='Compress rotated logs')

    results = parser.parse_args()

    # Check if some option is not set and set its default value

    if results.time == None:
        results.time = str(30)
    if results.rotate == None:
        results.rotate = str(3)
    if results.compress == None:
        results.compress = str(0)

    print('Execution time [s]   =', results.time)
    print('Max rotate files   =', results.rotate)
    print('Compress rotate files   =', results.compress)
    return results

def configure_wazuh(results, kind, sec, log_size):

    tree = ET.parse('/var/ossec/etc/ossec.conf')
    root = tree.getroot()
    logging = root.find('logging')
    # Change log rotation section values
    log = logging.find(kind)
    log_rotation = log.find('rotation')
    max_size = ET.SubElement(log_rotation, 'max_size')
    max_size.text = "{}M".format(log_size)
    interval = ET.SubElement(log_rotation, 'interval')
    interval.text = "{}s".format(sec)
    compress = ET.SubElement(log_rotation, 'compress')
    if int(results.compress) >= 1:
        compress.text = "yes"
    else:
        compress.text = "no"
    rotate = ET.SubElement(log_rotation, 'rotate')
    rotate.text = results.rotate
    # Write changes into configuration file
    tree.write("/var/ossec/etc/ossec.conf")

def clean_stop_wazuh():
    # Stop Wazuh, clean generated rotated logs and restore old ossec.conf
    os.system('systemctl stop wazuh-manager')
    os.system('rm -rf /var/ossec/logs/ossec/*')
    os.system('rm -rf /var/ossec/logs/alerts/*/')
    os.system('rm -rf /var/ossec/logs/archives/*/')
    os.system('cp ossec.conf.tmp /var/ossec/etc/ossec.conf')
    os.system('rm ossec.conf.tmp')

def clean_start_wazuh():
    # Comment monitord internal options, clean rotated logs if exist and restart manager
    os.system('cp internal_options_rotation.conf /var/ossec/etc/internal_options.conf')
    os.system('rm -rf /var/ossec/logs/ossec/*')
    os.system('rm -rf /var/ossec/logs/alerts/*/')
    os.system('rm -rf /var/ossec/logs/archives/*/')
    os.system('systemctl restart wazuh-manager')

def run_analysisd_valgrind(kind):

    os.system('/var/ossec/bin/ossec-control stop')
    os.system('rm -f /var/ossec/queue/fts/*')
    os.system('/var/ossec/bin/wazuh-db')
    os.system('/var/ossec/bin/ossec-execd')

    subprocess.Popen(["valgrind", "--track-fds=yes", "--leak-check=full", "--log-file=/home/report_{}_analysisd.log".format(kind), "/var/ossec/bin/ossec-analysisd"])

    not_run = os.system('/var/ossec/bin/ossec-control status | grep "analysisd is running"')
    while not_run != 0:
        not_run = os.system('/var/ossec/bin/ossec-control status | grep "analysisd is running"')

    os.system('/var/ossec/bin/ossec-syscheckd')
    os.system('/var/ossec/bin/ossec-remoted')
    os.system('/var/ossec/bin/ossec-logcollector')
    os.system('/var/ossec/bin/ossec-monitord')
    os.system('/var/ossec/bin/wazuh-modulesd')

if __name__ == "__main__":

    results = parse_arguments()

    print("Starting log rotation test...")

    # Configure Wazuh
    os.system('systemctl stop wazuh-manager')
    # Copy current configuration to restore later
    os.system('cp /var/ossec/etc/ossec.conf ossec.conf.tmp')

    t = int(results.time)

    ## Check monitord with interval rotation stress configuration
    print("Checking 'monitord' process with Valgrind during {} seconds...".format(t))
    configure_wazuh(results, "log", "1", "1")
    clean_start_wazuh()
    os.system('pkill -f ossec-monitord')
    subprocess.Popen(["valgrind", "--track-fds=yes", "--leak-check=full", "--log-file=/home/report_interval_monitor.log", "/var/ossec/bin/ossec-monitord"])
    time.sleep(t)
    print("Report in '/home/report_interval_monitord.log'")

    # Check analysisd with interval rotation stress configuration
    print("Checking 'analysisd' process with Valgrind...")
    os.system('/var/ossec/bin/ossec-control stop')
    configure_wazuh(results, "log", "1000", "1")
    configure_wazuh(results, "alerts", "1", "1")
    configure_wazuh(results, "archives", "1", "1")

    run_analysisd_valgrind("interval")
    time.sleep(t)
    print("Report in '/home/report_interval_analyisis.log'")
    os.system('ossec-control stop')

    ## Check monitord with size rotation stress configuration
    print("Checking 'monitord' process with Valgrind during {} seconds...".format(t))
    configure_wazuh(results, "log", "1000", "1")
    clean_start_wazuh()
    os.system('pkill -f ossec-monitord')
    subprocess.Popen(["./inject_log.sh", "logs"])
    subprocess.Popen(["valgrind", "--track-fds=yes", "--leak-check=full", "--log-file=/home/report_size_monitor.log", "/var/ossec/bin/ossec-monitord"])
    time.sleep(t)
    os.system('pkill -f inject_log')
    print("Report in '/home/report_size_monitord.log'")
#
    ## Check analysisd with interval rotation stress configuration
    print("Checking 'analysisd' process with Valgrind...")
    os.system('/var/ossec/bin/ossec-control stop')
    configure_wazuh(results, "alerts", "1000", "1")
    configure_wazuh(results, "archives", "1000", "1")
    run_analysisd_valgrind("size")
    subprocess.Popen(["./inject_log.sh", "alerts"])
    subprocess.Popen(["./inject_log.sh", "archives"])
    time.sleep(t)
    os.system('pkill -f inject_log')
    os.system('/var/ossec/bin/ossec-control stop')
    print("Report in '/home/report_size_analyisis.log'")
    print("Please check the Valgrind reports")

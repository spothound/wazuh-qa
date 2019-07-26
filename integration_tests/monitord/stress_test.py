#!/usr/bin/env python
# July 25, 2019

import os, time
import xml.etree.ElementTree as ET

if __name__ == "__main__":

    try:
        if sys.argv[1] == "-t":
            t = sys.argv[2]
            try:
                t = int(t)
            except ValueError:
                print("'-t' argument should be an integer")
                pass
        else:
            print("Argument should be '-n [N LOGS GENERATED]'")
            t = 60
    except:
        t = 60

    print("Starting stress test for log rotation...")

    print("Cleaning previous logs...")
    os.system('rm -rf /var/ossec/logs/ossec/*')
    os.system('rm -rf /var/ossec/logs/alerts/*/')
    os.system('rm -rf /var/ossec/logs/archives/*/')

    print("Configuring and restarting Wazuh...")

    # Parse XML
    tree = ET.parse('/var/ossec/etc/ossec.conf')
    root = tree.getroot()
    logging = root.find('logging')
    log = logging.find('log')
    log_rotation = log.find('rotation')
    log_rotation.find('interval').text = sec

    os.system('cp ossec_stress_1.conf /var/ossec/etc/ossec.conf')
    os.system('cp internal_options_size.conf /var/ossec/etc/internal_options.conf')
    os.system('systemctl restart wazuh-manager')
    print("Checking 'monitord' process with Valgrind during {} seconds...".format(t))
    os.system('pkill -f ossec-monitord')
    os.system('valgrind --track-fds=yes --leak-check=full --log-file=/home/report_monitor.log /var/ossec/bin/ossec-monitord')
    time.sleep(t)
    print("Report done in '/home/report_monitord.log'")
    print("Checking 'analysisd' process with Valgrind...")
    time.sleep
    os.system('/var/ossec/bin/ossec-control stop')
    os.system('cp ossec_stress_2.conf /var/ossec/etc/ossec.conf')
    os.system('./memory.sh')
    time.sleep(t)
    print("Report done in '/home/report_analyisis.log'")
    os.system('ossec-control stop')
    print("Please check the Valgrind reports")

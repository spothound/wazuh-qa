#!/usr/bin/env python
# July 23, 2019

import os, time, datetime, calendar, sys, argparse, fnmatch
import xml.etree.ElementTree as ET

ossec_logs_path = "/var/ossec/logs/ossec"
archives_logs_path = "/var/ossec/logs/archives"
alerts_logs_path = "/var/ossec/logs/alerts"

def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', action='store', dest='size',
                        help='Size for rotation [MB]')

    parser.add_argument('-n', action='store', dest='n',
                        help='Number of log rotations per format to wait')

    parser.add_argument('-r', action='store', dest='rotate',
                        help='Maximum number of permitted rotations in folder')

    parser.add_argument('-c', action='store', dest='compress',
                        help='Compress rotated logs')

    results = parser.parse_args()
    print('Size for rotation     =', results.size)
    print('Nº log rotations   =', results.n)
    print('Max rotate files   =', results.rotate)
    print('Compress rotate files   =', results.compress)
    return results

def assign_filename(kind, day, index, ext, compress):
    file_name = ""
    if index == 0:
        file_name = "ossec-{}-{}.{}".format(kind, day, ext)
    elif index > 0:
        if index < 10:
            file_name = "ossec-{}-{}-00{}.{}".format(kind, day, index, ext)
        elif index >= 10 and index < 100:
            file_name = "ossec-{}-{}-0{}.{}".format(kind, day, index, ext)
        elif index >= 100:
            file_name = "ossec-{}-{}-{}.{}".format(kind, day, index, ext)
        else:
            print("The index {} for a rotated log is not valid").format(index)
            return False

    if compress >= 1:
        file_name = "{}.gz".format(file_name)

    return file_name

def check_file(folder, file_name, file_name_prev, max_rotation, index, compress):
    # If a maximum number of rotated logs is set, check the file has been deleted
    if max_rotation >= 1 and index >= 0:
        file_path = "{}/{}".format(folder, file_name_prev)
        if os.path.exists(file_path):
            print("Rotated log file {} should have been overwritten by {}".format(file_name_prev, file_name))

    file_path = "{}/{}".format(folder, file_name)
    try:
        log_stats = os.stat(file_path)
    except Exception as e:
        print('# {0}'.format(e))
        return False

    # Check that the compressed file is not corrupted
    if compress == 1:
        value = os.system('gzip -t -v {}'.format(file_path))
        if value != 0:
            print("Compressed file {} is corrupted".format(file_path))
            return False
    else :
        print("{}: OK".format(file_path))

def check_rotation_files(date, path, kind, index, max_rotation, compress):
    month = date.date().month
    month = calendar.month_name[date.date().month]
    month = month[0:3]

    folder = "{}/{}/{}".format(path, date.date().year, month)

    file_name_prev = "-"
    file_name_json_prev = "-"
    index_2 = 0

    file_name_log = assign_filename(kind, date.date().day, index, "log", compress)
    file_name_json = assign_filename(kind, date.date().day, index, "json", compress)

    if max_rotation >= 1:
        index_2 = index - max_rotation
        file_name_prev = assign_filename(kind, date.date().day, index_2, "log", compress)
        file_name_json_prev = assign_filename(kind, date.date().day, index_2, "json", compress)

    # Check rotated files are created
    # Log format

    check_file(folder, file_name_log, file_name_prev, max_rotation, index_2, compress)

    # JSON format
    # Check previous rotate file doesn't exists

    check_file(folder, file_name_json, file_name_json_prev, max_rotation, index_2, compress)

    return True

def one_type_changed(folder_diff, compress):
    files_changed = len(folder_diff)

    if compress == 1:
        pattern_log = '*.log.gz'
        pattern_json = '*.json.gz'
        if files_changed == len(fnmatch.filter(folder_diff, pattern_log)) or files_changed == len(fnmatch.filter(folder_diff, pattern_json)):
            return 1
        else:
            return 0
    else:
        pattern_log = '*.log'
        pattern_json = '*.json'
        if files_changed == len(fnmatch.filter(folder_diff, pattern_log)) or files_changed == len(fnmatch.filter(folder_diff, pattern_json)):
            return 1
        else:
            return 0

def check_size_rotation(n, path, kind, max_rotation, max_size, compress):

    index = 0
    # Previous number of files in the rotation folder
    prev_rotation = sum([len(files) for r, d, files in os.walk(path)])

    p_dir = [ ]
    # Make a list of present files in the log rotation folder
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            p_dir.append(os.path.join(root, name))

    # Log path
    if kind == "logs":
        log_path = "/var/ossec/logs/ossec.log"
        json_path = "/var/ossec/logs/ossec.json"
        max_files = max_rotation * 2
    elif kind == "alerts":
        log_path = "/var/ossec/logs/alerts/alerts.log"
        json_path = "/var/ossec/logs/alerts/alerts.json"
        max_files = (max_rotation * 2) + 2
    elif kind == "archive":
        log_path = "/var/ossec/logs/archives/archives.log"
        json_path = "/var/ossec/logs/archives/archives.json"
        max_files = (max_rotation * 2) + 2
    else:
        print("Wrong kind of log: {}".format(kind))

    while n > 0:
        # Current number of files in the rotation folder
        act_rotation = sum([len(files) for r, d, files in os.walk(path)])

        c_dir = [ ]
        # Make a list of present files in the log rotation folder
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                c_dir.append(os.path.join(root, name))

        # Date of now
        now = datetime.datetime.now()

        # Log size
        size_log = os.stat(log_path).st_size
        size_json = os.stat(json_path).st_size

        # Check what files changed in the folder
        folder_diff = list(set(p_dir).symmetric_difference(set(c_dir)))
        # Check if only one format has changed
        otc = one_type_changed(folder_diff, compress)

        # A rotation file has appeared (json and log)
        if len(folder_diff) >= 2 and otc == 0 and len(list(set(p_dir).symmetric_difference(set(c_dir)))) % 2 == 0:
            if act_rotation > max_files:
                print("Maximum number of rotated logs has been surpassed in {}".format(path))
                return False
            # Check files created are correct
            ok = check_rotation_files(now, path, kind, index, max_rotation, compress)
            if ok == 0:
                return False

            index += 1
            n -= 1
            p_dir = c_dir

        if size_log > max_size or size_json > max_size:
            print("The size of '{}' is {} (.log) or {} (.json) that's above the specified limit in the configuration which is {}".format(kind, size_log, size_json, max_size))

        time.sleep(3)

    return True

def configure_wazuh(results, kind):

    tree = ET.parse('/var/ossec/etc/ossec.conf')
    root = tree.getroot()
    logging = root.find('logging')
    # Change log rotation section values
    log = logging.find(kind)
    log_rotation = log.find('rotation')
    max_size = ET.SubElement(log_rotation, 'max_size')
    max_size.text = "{}M".format(results.size)
    interval = ET.SubElement(log_rotation, 'interval')
    log_rotation.remove(interval)
    compress = ET.SubElement(log_rotation, 'compress')
    if int(results.compress) >= 1:
        compress.text = "yes"
    else:
        compress.text = "no"
    rotate = ET.SubElement(log_rotation, 'rotate')
    rotate.text = results.rotate
    # Write changes into configuration file
    tree.write("/var/ossec/etc/ossec.conf")

def show_test_result(kind, ok):
    if ok == 1:
        print("{} LOG SIZE ROTATION TEST... OK".format(kind))
    else:
        print("{} LOG SIZE ROTATION TEST... FAILED".format(kind))

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
    os.system('cp internal_options_size.conf /var/ossec/etc/internal_options.conf')
    os.system('rm -rf /var/ossec/logs/ossec/*')
    os.system('rm -rf /var/ossec/logs/alerts/*/')
    os.system('rm -rf /var/ossec/logs/archives/*/')
    os.system('systemctl restart wazuh-manager')

if __name__ == "__main__":

    results = parse_arguments()

    print("Starting size log rotation test...")

    # Configure Wazuh
    os.system('systemctl stop wazuh-manager')
    # Copy current configuration to restore later
    os.system('cp /var/ossec/etc/ossec.conf ossec.conf.tmp')

    # Parse XML
    configure_wazuh(results, "log")
    configure_wazuh(results, "alerts")
    configure_wazuh(results, "archives")

    clean_start_wazuh()

    n = int(results.n)
    size = int(results.size) * 1000000
    r = int(results.rotate)
    c = int(results.compress)

    # Check ossec logs
    print("Checking {} log rotations for each log type...".format(results.n))
    print("Checking rotation files in '{}'".format(ossec_logs_path))
    ok = check_size_rotation(n, ossec_logs_path, "logs", r, size, c)
    show_test_result("OSSEC", ok)

    print("Checking rotation files in '{}'".format(alerts_logs_path))
    ok = check_size_rotation(n, alerts_logs_path, "alerts", r, size, c)
    show_test_result("ALERTS", ok)

    os.system('touch {}/archives.json'.format(archives_logs_path))
    os.system('touch {}/archives.log'.format(archives_logs_path))

    print("Checking rotation files in '{}'".format(archives_logs_path))
    ok = check_size_rotation(n, archives_logs_path, "archive", r, size, c)
    show_test_result("ARCHIVES", ok)

    print("Stopping Wazuh and cleaning rotated logs...")
    clean_stop_wazuh()

    print("Test is over")

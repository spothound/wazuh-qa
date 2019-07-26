#!/usr/bin/env python
# July 23, 2019

import os, time, datetime, calendar, sys, gzip

ossec_logs_path = "/var/ossec/logs/ossec"
archives_logs_path = "/var/ossec/logs/archives"
alerts_logs_path = "/var/ossec/logs/alerts"

def check_rotation_files(date, path, kind, index):
    month = date.date().month
    month = calendar.month_name[date.date().month]
    month = month[0:3]

    folder = "{}/{}/{}".format(path, date.date().year, month)

    if index == 0:
        file_name = "ossec-{}-{}.log.gz".format(kind, date.date().day)
        file_name_json = "ossec-{}-{}.json.gz".format(kind, date.date().day)
    elif index > 0:
        if index < 10:
            file_name = "ossec-{}-{}-00{}.log.gz".format(kind, date.date().day, index)
            file_name_json = "ossec-{}-{}-00{}.json.gz".format(kind, date.date().day, index)
        elif index >= 10 and index < 100:
            file_name = "ossec-{}-{}-0{}.log.gz".format(kind, date.date().day, index)
            file_name_json = "ossec-{}-{}-0{}.json.gz".format(kind, date.date().day, index)
        elif index >= 100:
            file_name = "ossec-{}-{}-{}.log.gz".format(kind, date.date().day, index)
            file_name_json = "ossec-{}-{}-{}.json.gz".format(kind, date.date().day, index)
        else:
            print("The index {} for a rotated log is not valid").format(index)
            return False
    else:
        print("The index {} for a rotated log is not valid").format(index)
        return False

    # Check compressed rotated files are created
    # Log format
    file_path = "{}/{}".format(folder, file_name)
    try:
        log_stats = os.stat(file_path)
    except Exception as e:
        print('# {0}'.format(e))
        return False

    # Check compressed files are not corrupted
    value = os.system('gzip -t -v {}'.format(file_path))
    if value != 0:
        print("Compressed file {} is corrupted".format(file_path))
        return False

    # JSON format
    file_path = "{}/{}".format(folder, file_name_json)
    try:
        json_stats = os.stat(file_path)
    except Exception as e:
        print('# {0}'.format(e))
        return False

    value = os.system('gzip -t -v {}'.format(file_path))
    if value != 0:
        print("Compressed file {} is corrupted".format(file_path))
        return False

    return True

def check_interval_rotation(n):

    index_log = 0
    index_alerts = 0
    index_archives = 0

    prev_log_rot = sum([len(files) for r, d, files in os.walk(ossec_logs_path)])
    prev_alerts_rot = sum([len(files) for r, d, files in os.walk(alerts_logs_path)])
    prev_archives_rot = sum([len(files) for r, d, files in os.walk(archives_logs_path)])

    i = n * 3

    while i > 0:
        # Ossec logs
        act_log_rot = sum([len(files) for r, d, files in os.walk(ossec_logs_path)])
        act_alerts_rot = sum([len(files) for r, d, files in os.walk(alerts_logs_path)])
        act_archives_rot = sum([len(files) for r, d, files in os.walk(archives_logs_path)])

        now = datetime.datetime.now()

        # A rotation file has appeared
        if act_log_rot == prev_log_rot + 2:
            if index_log < n:
                # Check logs have been rotated correctly
                ok = check_rotation_files(now, ossec_logs_path, "logs", index_log)

                if ok == 0:
                    return False

                i -= 1
                index_log += 1

        prev_log_rot = act_log_rot

        # Alerts logs
        if act_alerts_rot == prev_alerts_rot + 2:
            if index_alerts < n:
                # Check logs have been rotated correctly
                ok = check_rotation_files(now, alerts_logs_path, "alerts", index_alerts)

                if ok == 0:
                    return False

                i -= 1
                index_alerts += 1

        prev_alerts_rot = act_alerts_rot

        # Archives logs
        if act_archives_rot == prev_archives_rot + 2:
            if index_archives < n:
                # Check logs have been rotated correctly
                ok = check_rotation_files(now, archives_logs_path, "archive", index_archives)

                if ok == 0:
                    return False

                i -= 1
                index_archives += 1

        prev_archives_rot = act_archives_rot
        time.sleep(3)

    return True

if __name__ == "__main__":

    try:
        if sys.argv[1] == "-n":
            n = sys.argv[2]
            try:
                n = int(n)
            except ValueError:
                print("'-n' argument should be an integer")
                pass
        else:
            print("Argument should be '-n [N LOGS GENERATED]'")
            n = 5
    except:
        n = 5

    print("Starting interval log rotation test...")

    # Interval test

    # Configure Wazuh
    os.system('cp ossec_interval.conf /var/ossec/etc/ossec.conf')
    os.system('systemctl restart wazuh-manager')

    # Check ossec logs
    print("Checking {} log rotations for each log type...".format(n))
    ok = check_interval_rotation(n)
    if ok == 1:
        print("INTERVAL ROTATION TEST... OK")
    else:
        print("INTERVAL ROTATION TEST... FAILED")

    print("Stopping Wazuh and cleaning rotated logs...")
    os.system('systemctl stop wazuh-manager')
    os.system('rm -rf /var/ossec/logs/ossec/*')
    os.system('rm -rf /var/ossec/logs/alerts/*')
    os.system('rm -rf /var/ossec/logs/archives/*')
    print("Test is over")

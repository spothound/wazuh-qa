from wazuh_testing.tools import monitoring

def callback_analyzing_file(file):
    msg = fr"INFO: \(\d+\): Analyzing file: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_monitoring_command(log_format, command):
    msg = fr"INFO: Monitoring output of {command}\(\d+\): {log_format}"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)

def callback_monitoring_djb_multilog(program_name, multilog_file):
    msg = fr"INFO: Using program name '{program_name}' for DJB multilog file: '{multilog_file}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)

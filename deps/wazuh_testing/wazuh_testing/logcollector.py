from wazuh_testing.tools import monitoring


def callback_analyzing_file(file):
    msg = fr"INFO: \(\d+\): Analyzing file: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_monitoring_command(log_format, command):
    log_format_message = 'full output' if log_format == 'full_command' else 'output'
    msg = fr"INFO: Monitoring {log_format_message} of command\(\d+\): {command}"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_monitoring_djb_multilog(program_name, multilog_file):
    msg = fr"INFO: Using program name '{program_name}' for DJB multilog file: '{multilog_file}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)


def callback_command_alias_output(alias):
    msg = fr"Reading command message: 'ossec: output: '{alias}':"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)
from wazuh_testing.tools import monitoring

GENERIC_CALLBACK_ERROR_COMMAND_MONITORING = 'The expected command monitoring log has not been produced'
GENERIC_CALLBACK_ERROR_INVALID_LOCATION = 'The expected invalid location error log has not been produced'
GENERIC_CALLBACK_ERROR_ANALYZING_FILE = 'The expected analyzing file log has not been produced'
GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL = "The expected analyzing eventchannel log has not been produced"
GENERIC_CALLBACK_ERROR_TARGET_SOCKET = "The expected target socket log has not been produced"
GENERIC_CALLBACK_ERROR_TARGET_SOCKET_NOT_FOUND = "The expected target socket not found error has not been produced"

def callback_analyzing_file(file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"Analyzing file: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_monitoring_command(log_format, command, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    log_format_message = 'full output' if log_format == 'full_command' else 'output'
    msg = fr"INFO: Monitoring {log_format_message} of command\(\d+\): {command}"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_monitoring_djb_multilog(program_name, multilog_file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"INFO: Using program name '{program_name}' for DJB multilog file: '{multilog_file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_command_alias_output(alias, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"Reading command message: 'ossec: output: '{alias}':"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_eventchannel_bad_format(event_location, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"ERROR: Could not EvtSubscribe() for ({event_location}) which returned \(\d+\)"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_socket_target(location, socket_name, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"DEBUG: Socket target for '{location}' -> {socket_name}"
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_socket_not_defined(location, socket_name, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"CRITICAL: Socket '{socket_name}' for '{location}' is not defined."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_log_target_not_found(location, socket_name, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"WARNING: Log target '{socket_name}' not found for the output format of localfile '{location}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_invalid_reconnection_time(severity='WARNING', default_value='5', prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"{severity}: Invalid reconnection time value. Changed to {default_value} seconds."
    return monitoring.make_callback(pattern=msg, prefix=prefix)


def callback_eventchannel_analyzing(event_location):
    msg = fr"INFO: \(\d+\): Analyzing event log: '{event_location}'"
    return monitoring.make_callback(pattern=msg, prefix=monitoring.AGENT_DETECTOR_PREFIX)


def callback_invalid_location_pattern(location, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"Glob error. Invalid pattern: '{location}' or no files found."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_ignoring_file(location_file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"DEBUG: Ignoring file '{location_file}' due to modification time"
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)


def callback_file_matches_pattern(location_pattern, location_file, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX):
    msg = fr"New file that matches the '{location_pattern}' pattern: '{location_file}'."
    return monitoring.make_callback(pattern=msg, prefix=prefix, escape=True)

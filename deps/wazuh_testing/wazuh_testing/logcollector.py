from wazuh_testing.tools import monitoring

def callback_analyzing_file(file):
    msg = fr"Info: \(\d+\): Analyzing file: '{file}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.LOG_COLLECTOR_DETECTOR_PREFIX)

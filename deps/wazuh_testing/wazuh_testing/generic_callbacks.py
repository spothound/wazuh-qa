from wazuh_testing.tools import WAZUH_CONF
from wazuh_testing.tools import monitoring

def callback_invalid_value(option, value, wazuh_daemon):
    """Create a callback to detect invalid values in ossec.conf file.

    Args:
        option (str): Wazuh manager configuration option.
        value (str): Value of the configuration option.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"ERROR: \(\d+\): Invalid value for element '{option}': {value}."
    return monitoring.make_callback(pattern=msg, prefix=wazuh_daemon)


def callback_error_in_configuration(severity, wazuh_daemon):
    """Create a callback to detect configuration error in ossec.conf file.

    Args:
        severity (str): ERROR or CRITICAL.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"{severity}: \(\d+\): Configuration error at '{WAZUH_CONF}'."
    return monitoring.make_callback(pattern=msg, prefix=wazuh_daemon)


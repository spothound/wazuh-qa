from wazuh_testing.tools import WAZUH_CONF
from wazuh_testing.tools import monitoring



def callback_invalid_value(option, value):
    """Create a callback to detect invalid values in ossec.conf file.

    Args:
        option (str): Wazuh manager configuration option.
        value (str): Value of the configuration option.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"ERROR: \(\d+\): Invalid value for element '{option}': {value}."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.REMOTED_DETECTOR_PREFIX)


def callback_error_in_configuration(severity):
    """Create a callback to detect configuration error in ossec.conf file.

    Args:
        severity (str): ERROR or CRITICAL.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"{severity}: \(\d+\): Configuration error at '{WAZUH_CONF}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.REMOTED_DETECTOR_PREFIX)


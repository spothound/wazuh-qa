from wazuh_testing.tools import WAZUH_CONF
from wazuh_testing.tools import monitoring


def callback_error_in_configuration(severity):
    """Create a callback to detect configuration error in ossec.conf file.

    Args:
        severity (str): ERROR or CRITICAL.

    Returns:
        callable: callback to detect this event.
    """
    msg = fr"{severity}: \(\d+\): Configuration error at '{WAZUH_CONF}'."
    return monitoring.make_callback(pattern=msg, prefix=monitoring.REMOTED_DETECTOR_PREFIX)

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.remote as remote
import wazuh_testing.generic_callbacks as gc
from wazuh_testing.tools import LOG_COLLECTOR_DETECTOR_PREFIX
# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'json'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'snort-full'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'eventlog'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'eventchannel'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'mysql_log'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'postgresql_log'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'nmapg'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'iis'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'full_command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'djb-multilog'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'multi-line'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'invalid'},

]

metadata = [
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'json', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'snort-full', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'eventlog', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'eventchannel', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'mysql_log', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'postgresql_log', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'nmapg', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'iis', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'command', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'full_command', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'djb-multilog', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'multi-line', 'valid': True},
    {'location': '/tmp/test.txt', 'log_format': 'invalid', 'valid': False},
]


configurations = load_wazuh_configurations(configurations_path, "test_configuration_location",
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_log_format_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid']:
        pytest.skip('Invalid values provided')

    # Check API response and log format analysing file
    assert 1


def test_log_format_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']

    if cfg['valid']:
        pytest.skip('Valid values provided')

    log_callback = gc.callback_invalid_value('log_format', cfg['log_format'], LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('CRITICAL', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")


"""
2021/03/15 11:09:46 wazuh-logcollector: INFO: (1950): Analyzing file: 'file.txt'.
"""

"""
2021/03/15 12:39:49 wazuh-logcollector: ERROR: (1235): Invalid value for element 'log_format': invalid.
2021/03/15 12:39:49 wazuh-logcollector: ERROR: (1202): Configuration error at '/var/ossec/etc/ossec.conf'.
2021/03/15 12:39:49 wazuh-logcollector: CRITICAL: (1202): Configuration error at '/var/ossec/etc/ossec.conf'.
"""






















# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.logcollector as logcollector
import wazuh_testing.generic_callbacks as gc
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX
# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'json', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'snort-full', 'COMMAND': 'example-command'},
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventlog', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'eventchannel', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'mysql_log', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'postgresql_log', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'nmapg', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'iis', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'command', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'command', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'full_command', 'COMMAND': 'example-command'},
    {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog', 'COMMAND': 'example-command'},
    {'LOCATION': '/var/log/program_name_testing/current', 'LOG_FORMAT': 'djb-multilog', 'COMMAND': 'example-command'},
    {'LOCATION': '/var/log/testing/current', 'LOG_FORMAT': 'djb-multilog', 'COMMAND': 'example-command'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'multi-line:3'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'invalid'},

]

metadata = [
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'json', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'snort-full', 'command': 'example-command', 'valid_value': True},
    {'location': 'Security', 'log_format': 'eventlog', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'eventchannel', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'mysql_log', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'postgresql_log', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'nmapg', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'iis', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'command', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': '', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'full_command', 'command': 'example-command', 'valid_value': True},
    {'location': '/var/log/testing/current', 'log_format': 'djb-multilog', 'command': 'example-command', 'valid_value': True},
    {'location': '/var/log/program_name_testing/current', 'log_format': 'djb-multilog', 'command': 'example-command', 'valid_value': True},
    {'location': '/var/log/testing/current', 'log_format': 'djb-multilog', 'command': 'example-command','valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'multi-line:3', 'command': 'example-command', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'invalid', 'command': 'example-command', 'valid_value': False}
]


configurations = load_wazuh_configurations(configurations_path, "test_configuration_location",
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT']}" for x in parameters]

log_format_not_print_analyzing_info = ['command', 'full_command', 'eventlog', 'eventchannel']

# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_log_format_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')

    if cfg['log_format'] not in log_format_not_print_analyzing_info :

        log_callback = logcollector.callback_analyzing_file(cfg['location'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")
    elif 'command' in cfg['log_format']:

        log_callback = logcollector.callback_monitoring_command(cfg['location'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    elif cfg['log_format'] == 'djb-multilog':

        log_callback = logcollector.callback_monitoring_djb_multilog(cfg['location'])
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message="The expected error output has not been produced")

    # Check API response and log format analysing file


def test_log_format_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']

    if cfg['valid_value']:
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

FAILED test_logcollector/test_configuration/test_configuration_log_format.py::test_log_format_valid[('Securifdhsakfjasty', 'eventlog')]
FAILED test_logcollector/test_configuration/test_configuration_log_format.py::test_log_format_valid[('/tmp/test.txt', 'eventchannel')]
FAILED test_logcollector/test_configuration/test_configuration_log_format.py::test_log_format_valid[('/tmp/test.txt', 'command')]
FAILED test_logcollector/test_configuration/test_configuration_log_format.py::test_log_format_valid[('/tmp/test.txt', 'full_command')]
FAILED test_logcollector/test_configuration/test_configuration_log_format.py::test_log_format_valid[('/tmp/test.txt', 'djb-multilog')]


Command

2021/03/15 15:32:17 wazuh-logcollector: INFO: Monitoring output of command(360): command

Full command
2021/03/15 15:31:39 wazuh-logcollector: INFO: Monitoring output of command(360): full_command



djb-multilog
2021/03/15 15:34:59 wazuh-logcollector: INFO: Using program name 'testing' for DJB multilog file: '/var/log/testing/current'.




Not show log: evenchannel, eventlog

"""
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
import wazuh_testing.api as api
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX
import wazuh_testing.generic_callbacks as gc

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')


if sys.platform == 'win32':
    parameters = [
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\file.txt'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\*.txt'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\file.*'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\file.*'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': r'C:\tmp\*', 'EXCLUDE': r'C:\tmp\file.log-%Y-%m-%d'},
    ]

    metadata = [
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\file.txt', 'valid_value': True},
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\*.txt', 'valid_value': True},
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\file.*', 'valid_value': True},
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\file.*', 'valid_value': True},
        {'log_format': 'syslog', 'location': r'C:\tmp\*', 'exclude': r'C:\tmp\file.log-%Y-%m-%d', 'valid_value': True},
    ]

else:
    parameters = [
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/file.txt'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/f*'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/*g'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/file?.txt'},
        {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing/*', 'EXCLUDE': '/tmp/testing/file.log-%Y-%m-%d'},
    ]

    metadata = [
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/file.txt', 'valid_value': True},
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/f*', 'valid_value': True},
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/*g', 'valid_value': True},
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/file?.txt',
         'valid_value': True},
        {'log_format': 'syslog', 'location': '/tmp/testing/*', 'exclude': '/tmp/testing/file.log-%Y-%m-%d',
         'valid_value': True},
    ]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['LOCATION'], x['EXCLUDE']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_exclude_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')

    api_answer = api.get_manager_configuration(section='localfile')[0]
    for field in cfg.keys():
        if field != 'valid_value':
            assert str(cfg[field]) in str(api_answer[field]), "Wazuh API answer different from introduced configuration"


def test_configuration_exclude_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = gc.callback_invalid_value('exclude', cfg['exclude'], LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('CRITICAL', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

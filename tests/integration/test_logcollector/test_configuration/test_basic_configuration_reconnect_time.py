# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
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

parameters = [
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '3s'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '4000s'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '5m'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '99h'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '94201d'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '44sTesting'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': 'Testing44s'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '9hTesting'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '400mTesting'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': '3992'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': '/tmp/testing.txt', 'RECONNECT_TIME': 'Testing'},
]

metadata = [
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '3s'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '4000s'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '5m'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '99h'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '94201d'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '44sTesting'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': 'Testing44s'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '9hTesting'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '400mTesting'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': '3992'},
    {'log_format': 'syslog', 'location': '/tmp/testing.txt', 'reconnect_time': 'Testing'},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['LOCATION'], x['RECONNECT_TIME']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_age_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')

    api_answer = api.get_manager_configuration(section='localfile')[0]
    for field in cfg.keys():
        if field != 'valid_value':
            assert str(cfg[field]) in str(api_answer[field]), "Wazuh API answer different from introduced configuration"


def test_configuration_age_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = gc.callback_invalid_value('reconnect_time', cfg['reconnect_time'], LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('CRITICAL', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.api as api
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')
local_internal_options = {
    'logcollector.debug': 2
}
parameters = [
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'yes'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'no'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'yesTesting'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'noTesting'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': 'testingvalue'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog', 'ONLY_FUTURE_EVENTS': '1234'}

]

metadata = [
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'only-future-events': 'yes', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'only-future-events': 'no', 'valid_value': True},
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'only-future-events': 'yesTesting', 'valid_value': False},
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'only-future-events': 'noTesting', 'valid_value': False},
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'only-future-events': 'testingvalue', 'valid_value': False},
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'only-future-events': '1234', 'valid_value': False}

]


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['ONLY_FUTURE_EVENTS']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_only_future_events_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')

    api_answer = api.get_manager_configuration(section='localfile')[0]
    for field in cfg.keys():
        if field != 'valid_value':
            assert str(cfg[field]) in str(api_answer[field]), "Wazuh API answer different from introduced configuration"


def test_only_future_events_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = gc.callback_invalid_value('only-future-events', cfg['only-future-events'],
                                             LOG_COLLECTOR_DETECTOR_PREFIX, severity="WARNING")
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")


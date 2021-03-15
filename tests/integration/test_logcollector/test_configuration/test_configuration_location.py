# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import wazuh_testing.remote as remote

from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog'},

]

metadata = [
    {'location': '/tmp/test.txt', 'log_format': 'syslog'},
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


def test_location_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']

    if not cfg['valid'] :
        pytest.skip('Valid values for location provided')

    assert 1


def test_location_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    if cfg['valid']:
        pytest.skip('UDP only supports one message per datagram.')

    log_callback = remote.callback_invalid_value('connection', cfg['connection'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = remote.callback_error_in_configuration('ERROR')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = remote.callback_error_in_configuration('CRITICAL')
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")


"""
2021/03/15 11:09:46 wazuh-logcollector: INFO: (1950): Analyzing file: 'file.txt'.
"""
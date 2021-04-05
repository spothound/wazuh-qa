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
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing', 'FREQUENCY': '3'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing', 'FREQUENCY': '10'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing', 'FREQUENCY': '100000'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing', 'FREQUENCY': '3s'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing', 'FREQUENCY': 'Testing'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing', 'FREQUENCY': '3Testing'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing', 'FREQUENCY': '3s5m'},
    {'LOG_FORMAT': 'command', 'COMMAND': 'echo Testing', 'FREQUENCY': 'Testing3'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing', 'FREQUENCY': '3'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing', 'FREQUENCY': '10'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing', 'FREQUENCY': '100000'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing', 'FREQUENCY': '3s'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing', 'FREQUENCY': 'Testing'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing', 'FREQUENCY': '3Testing'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing', 'FREQUENCY': '3s5m'},
    {'LOG_FORMAT': 'full_command', 'COMMAND': 'echo Testing', 'FREQUENCY': 'Testing3'},

]

metadata = [
    {'log_format': 'command', 'command': 'echo Testing', 'frequency': '3', 'valid_value': True},
    {'log_format': 'command', 'command': 'echo Testing', 'frequency': '10', 'valid_value': True},
    {'log_format': 'command', 'command': 'echo Testing', 'frequency': '100000', 'valid_value': True},
    {'log_format': 'command', 'command': 'echo Testing', 'frequency': '3s', 'valid_value': False},
    {'log_format': 'command', 'command': 'echo Testing', 'frequency': 'Testing', 'valid_value': False},
    {'log_format': 'command', 'command': 'echo Testing', 'frequency': '3Testing', 'valid_value': False},
    {'log_format': 'command', 'command': 'echo Testing', 'frequency': '3s5m', 'valid_value': False},
    {'log_format': 'command', 'command': 'echo Testing', 'frequency': 'Testing3', 'valid_value': False},
    {'log_format': 'full_command', 'command': 'echo Testing', 'frequency': '3', 'valid_value': True},
    {'log_format': 'full_command', 'command': 'echo Testing', 'frequency': '10', 'valid_value': True},
    {'log_format': 'full_command', 'command': 'echo Testing', 'frequency': '100000', 'valid_value': True},
    {'log_format': 'full_command', 'command': 'echo Testing', 'frequency': '3s', 'valid_value': False},
    {'log_format': 'full_command', 'command': 'echo Testing', 'frequency': 'Testing', 'valid_value': False},
    {'log_format': 'full_command', 'command': 'echo Testing', 'frequency': '3Testing', 'valid_value': False},
    {'log_format': 'full_command', 'command': 'echo Testing', 'frequency': '3s5m', 'valid_value': False},
    {'log_format': 'full_command', 'command': 'echo Testing', 'frequency': 'Testing3', 'valid_value': False},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOG_FORMAT'], x['COMMAND'], x['FREQUENCY']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_frequency_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')

    api_answer = api.get_manager_configuration(section='localfile')[0]
    for field in cfg.keys():
        if field != 'valid_value':
            assert str(cfg[field]) in str(api_answer[field]), "Wazuh API answer different from introduced configuration"


def test_configuration_frequency_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = gc.callback_invalid_value('frequency', cfg['frequency'], LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('CRITICAL', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

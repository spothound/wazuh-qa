# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
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
    location = r'C:\testing\file.txt'
else:
    location = '/tmp/testing.txt'

parameters = [
    {'LOCATION': f'{location}', 'AGE': '3s'},
    {'LOCATION': f'{location}', 'AGE': '4000s'},
    {'LOCATION': f'{location}', 'AGE': '5m'},
    {'LOCATION': f'{location}', 'AGE': '99h'},
    {'LOCATION': f'{location}', 'AGE': '94201d'},
    {'LOCATION': f'{location}', 'AGE': '44sTesting'},
    {'LOCATION': f'{location}', 'AGE': 'Testing44s'},
    {'LOCATION': f'{location}', 'AGE': '9hTesting'},
    {'LOCATION': f'{location}', 'AGE': '400mTesting'},
    {'LOCATION': f'{location}', 'AGE': '3992'},
    {'LOCATION': f'{location}', 'AGE': 'Testing'},
]

metadata = [
    {'location': f'{location}', 'age': '3s', 'valid_value': True},
    {'location': f'{location}', 'age': '4000s', 'valid_value': True},
    {'location': f'{location}', 'age': '5m', 'valid_value': True},
    {'location': f'{location}', 'age': '99h', 'valid_value': True},
    {'location': f'{location}', 'age': '94201d', 'valid_value': True},
    {'location': f'{location}', 'age': '44sTesting', 'valid_value': False},
    {'location': f'{location}', 'age': 'Testing44s', 'valid_value': False},
    {'location': f'{location}', 'age': '9hTesting', 'valid_value': False},
    {'location': f'{location}', 'age': '400mTesting', 'valid_value': False},
    {'location': f'{location}', 'age': '3992', 'valid_value': False},
    {'location': f'{location}','age': 'Testing', 'valid_value': False},
]

for _ in len(parameters):
    parameters['LOCATION'] = location
    metadata['location'] = location


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['AGE']}" for x in parameters]


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

    real_configuration = cfg.copy()
    real_configuration.pop('valid_value')
    api.compare_config_api_response(real_configuration, 'localfile')


def test_configuration_age_invalid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if cfg['valid_value']:
        pytest.skip('Invalid values provided')

    log_callback = gc.callback_invalid_value('age', cfg['age'], LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('CRITICAL', LOG_COLLECTOR_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")
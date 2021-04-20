# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
import sys
import wazuh_testing.api as api
from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
import wazuh_testing.generic_callbacks as gc
import wazuh_testing.logcollector as logcollector

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')
wazuh_component = get_service()


if sys.platform == 'win32':
    location = r'C:\testing\file.txt'
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    location = '/tmp/testing.txt'
    wazuh_configuration = 'etc/ossec.conf'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '3s'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '4000s'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog', 'AGE': '5m'},
]
metadata = [
    {'location': f'{location}', 'log_format': 'syslog', 'age': '3s', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '4000s', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'age': '5m', 'valid_value': True},
]

problematic_values = ['44sTesting', '9hTesting', '400mTesting', '3992']
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['AGE']}" for x in parameters]


@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_age(get_files_list, create_file, get_configuration, configure_environment, restart_logcollector):
    # Create a fixture to create file structure
    # Check files are monitored
    # Change system datetime
    # restart
    # Fixture remove created files:
    # Check that it ignore the file:
    # Edit the file >> Testing file monitoring with age
    # Check it the file is monitored
    assert 1 == 1

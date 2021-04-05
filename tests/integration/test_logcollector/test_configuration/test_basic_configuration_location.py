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
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': 'Microsoft-Windows-Sysmon/Operational', 'LOG_FORMAT': 'eventchannel'},
    {'LOCATION': r'C:\Users\wazuh\myapp\*', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 'LOG_FORMAT': 'eventchannel'},
    {'LOCATION': r'C:\xampp\apache\logs\*.log', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': r'C:\logs\file-%Y-%m-%d.log', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': '/*', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': 'Testing white spaces', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': r'/tmp/%F%H%K%L/*', 'LOG_FORMAT': 'syslog'},
]

metadata = [
    {'location': '/tmp/test.txt', 'log_format': 'syslog', 'valid_value': True},
    {'location': 'Microsoft-Windows-Sysmon/Operational', 'log_format': 'eventchannel',
     'valid_value': True},
    {'location': r'C:\Users\wazuh\myapp', 'log_format': 'syslog',
     'valid_value': True},
    {'location': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 'log_format': 'eventchannel',
     'valid_value': True},
    {'location': r'C:\xampp\apache\logs\*.log', 'log_format': 'syslog', 'valid_value' : True},
    {'location': r'C:\logs\file-%Y-%m-%d.log', 'log_format': 'syslog', 'valid_value': True},
    {'location': '/*', 'log_format': 'syslog', 'valid_value': True},
    {'location': 'Testing white spaces', 'log_format': 'syslog', 'valid_value': True},
    {'location': r'/tmp/%F%H%K%L/*', 'log_format': 'syslog', 'valid_value': True},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_location_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    cfg = get_configuration['metadata']
    if not cfg['valid_value']:
        pytest.skip('Invalid values provided')

    api_answer = api.get_manager_configuration(section='localfile')[0]
    for field in cfg.keys():
        if field != 'valid_value':
            assert str(cfg[field]) in str(api_answer[field]), "Wazuh API answer different from introduced configuration"
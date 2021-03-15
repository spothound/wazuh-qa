# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

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

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_location",
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_location_valid(get_configuration, configure_environment, restart_remoted):
    """
    """
    cfg = get_configuration['metadata']
    assert 1


def test_location_invalid(get_configuration, configure_environment, restart_remoted):
    """
    """
    assert 1


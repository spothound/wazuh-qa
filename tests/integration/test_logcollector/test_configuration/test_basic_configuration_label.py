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
    {'LABEL': 'myapp', 'KEY': '@source'},
]
metadata = [
    {'label': 'myapp', 'key': '@source'},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LABEL'], x['KEY']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_frequency_valid(get_configuration, configure_environment, restart_logcollector):
    """
    """
    api_answer = api.get_manager_configuration(section='localfile')[0]
    for field in cfg.keys():
        if field != 'valid_value':
            assert str(cfg[field]) in str(api_answer[field]), "Wazuh API answer different from introduced configuration"


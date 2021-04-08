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
    {'LABEL': 'myapp', 'KEY': 'agent.type'},
    {'LABEL': 'myapp', 'KEY': 'agent.location'},
    {'LABEL': 'myapp', 'KEY': 'agent.idgroup'},
    {'LABEL': 'myapp', 'KEY': 'group.groupnname'},
    {'LABEL': 'myapp', 'KEY': '109304'},
    {'LABEL': 'myapp', 'KEY': 'TestingTagNames'},
    {'LABEL': 'myapp', 'KEY': '?¿atag_tname'},
]
metadata = [
    {'label': 'myapp', 'key': '@source'},
    {'label': 'myapp', 'key': 'agent.type'},
    {'label': 'myapp', 'key': 'agent.location'},
    {'label': 'myapp', 'key': 'agent.idgroup'},
    {'label': 'myapp', 'key': 'group.groupnname'},
    {'label': 'myapp', 'key': '109304'},
    {'label': 'myapp', 'key': 'TestingTagNames'},
    {'label': 'myapp', 'key': '?¿atag_tname'}
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
    cfg = get_configuration['metadata']

    api_answer = api.get_manager_configuration(section='localfile')[0]
    api_label_key = str(api_answer['label']['key'])
    api_label_item = str(api_answer['label']['item'])
    assert cfg['label'] == api_label_item
    assert cfg['key'] == api_label_key


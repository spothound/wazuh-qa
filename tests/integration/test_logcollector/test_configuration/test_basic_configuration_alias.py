# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools.configuration import load_wazuh_configurations
import wazuh_testing.logcollector as logcollector
import wazuh_testing.api as api


# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')
local_internal_options = {
    'logcollector.debug': 2
}
parameters = [
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'command', 'COMMAND': 'echo TESTING', 'ALIAS': 'alias'},
    {'LOCATION': '/tmp/test.txt', 'LOG_FORMAT': 'full_command', 'COMMAND': 'echo TESTING', 'ALIAS': 'alias2'}
]

metadata = [
    {'location': '/tmp/test.txt', 'log_format': 'command', 'command': 'echo TESTING', 'alias': 'alias'},
    {'location': '/tmp/test.txt', 'log_format': 'full_command', 'command': 'echo TESTING', 'alias': 'alias2'}
]


configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['COMMAND'], x['ALIAS']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_configuration_alias(get_configuration, configure_environment, restart_logcollector):
    """
    """

    cfg = get_configuration['metadata']

    log_callback = logcollector.callback_command_alias_output(cfg['alias'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    api_answer = api.get_manager_configuration(section='localfile')[0]
    for field in cfg.keys():
        assert str(cfg[field]) in str(api_answer[field]), "Wazuh API answer different from introduced configuration"
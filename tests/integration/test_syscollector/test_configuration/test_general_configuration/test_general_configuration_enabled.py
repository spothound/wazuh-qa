# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.syscollector import callback_detect_syscollector_enabled, \
                                        callback_detect_syscollector_disabled, \
                                        SYSCOLLECTOR_GLOBAL_TIMEOUT

# Marks
pytestmark = pytest.mark.tier(level=0)

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_enabled.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

parameters = [{'DISABLED': 'no', 'TAG': 'enabled'}, 
              {'DISABLED': 'yes', 'TAG': 'disabled'}]
metadata= [{'disabled': 'no'}, 
           {'disabled': 'yes'}]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.parametrize('tags_to_apply, custom_callback, custom_error_message', [
    ({'enabled'}, callback_detect_syscollector_enabled, 'Syscollector is disabled'),
    ({'disabled'}, callback_detect_syscollector_disabled, 'Syscollector is enabled')
])
def test_enabled(tags_to_apply, custom_callback, custom_error_message, get_configuration, configure_environment,
                 restart_modulesd):
    """
    Check if the disabled parameter works as intended:
    Syscollector is activated when disabled is set to 'yes' and does
    not activated when disabled is set to 'yes'.
    """

    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=SYSCOLLECTOR_GLOBAL_TIMEOUT, callback=custom_callback,
                            error_message=custom_error_message)

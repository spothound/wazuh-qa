# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import shutil

import pytest
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor


@pytest.fixture(scope='module')
def configure_local_rules(get_configuration, request):
    """Configure a custom rule in local_rules.xml for testing. Restart Wazuh is needed for applying the
    configuration. """

    # save current configuration
    shutil.copy('/var/ossec/etc/rules/local_rules.xml', '/var/ossec/etc/rules/local_rules.xml.cpy')

    # configuration for testing
    file_test = str(get_configuration)
    shutil.copy(file_test, '/var/ossec/etc/rules/local_rules.xml')

    yield

    # restore previous configuration
    shutil.move('/var/ossec/etc/rules/local_rules.xml.cpy', '/var/ossec/etc/rules/local_rules.xml')


@pytest.fixture(scope='module')
def wait_for_analysisd_startup(request):
    """Wait until analysisd has begun and alerts.json is created."""

    def callback_analysisd_startup(line):
        if 'Input message handler thread started.' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_analysisd_startup)

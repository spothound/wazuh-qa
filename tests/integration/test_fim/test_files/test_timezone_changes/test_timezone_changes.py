# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import time

import pytest
from wazuh_testing.fim import (LOG_FILE_PATH, REGULAR, callback_detect_event, callback_detect_end_scan, create_file,
                               generate_params, delete_file, global_parameters, check_time_travel)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=2)

# variables

testdir1 = os.path.join(PREFIX, 'testdir1')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_timezone_conf.yaml')

# configurations

conf_params = {'TEST_DIRECTORIES': testdir1, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def set_local_timezone():
    if sys.platform == 'win32':
        os.system('tzutil /s "Romance Standard Time"')
    else:
        os.environ['TZ'] = 'Europe/Madrid'
        time.tzset()


def set_foreign_timezone():
    if sys.platform == 'win32':
        os.system('tzutil /s "Egypt Standard Time"')
    else:
        os.environ['TZ'] = 'Asia/Tokyo'
        time.tzset()


def callback_detect_event_before_end_scan(line):
    ended_scan = callback_detect_end_scan(line)
    if ended_scan is None:
        event = callback_detect_event(line)
        assert event is None, 'Event detected before end scan'
        return None
    else:
        return True


def extra_configuration_before_yield():
    set_local_timezone()
    create_file(REGULAR, testdir1, 'regular', content='')


def extra_configuration_after_yield():
    delete_file(testdir1, 'regular')
    set_local_timezone()


def test_timezone_changes(get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    """
    Check if events are appearing after the baseline
    The message 'File integrity monitoring scan ended' informs about the end of the first scan,
    which generates the baseline

    It creates a file, checks if the baseline has generated before the file addition event, and then
    if this event has generated.
    """
    check_apply_test({'timezone_conf'}, get_configuration['tags'])

    # Change time zone
    set_foreign_timezone()

    check_time_travel(True, monitor=wazuh_log_monitor)

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event_before_end_scan,
                            error_message='Did not receive expected event before end the scan')

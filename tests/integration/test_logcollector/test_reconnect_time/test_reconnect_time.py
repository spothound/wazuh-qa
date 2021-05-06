# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
from datetime import timedelta, datetime

import sys
from wazuh_testing.tools.configuration import load_wazuh_configurations
import win32evtlogutil
import win32evtlog
from wazuh_testing import global_parameters, logger
from wazuh_testing.tools.time import TimeMachine
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX

if sys.platform != 'win32':
    pytestmark = [pytest.mark.skip, pytest.mark.tier(level=0)]
else:
    pytestmark = pytest.mark.tier(level=0)

local_internal_options = {
    'logcollector.remote_commands': 1,
    'logcollector.debug': 2,
    'monitord.rotate_log': 0
}

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_test_reconnect_time..yaml')

parameters = [
    {'LOCATION': 'Application', 'LOG_FORMAT': 'eventchannel', 'RECONNECT_TIME': '5'},
    {'LOCATION': 'Security', 'LOG_FORMAT': 'eventchannel', 'RECONNECT_TIME': '5'},
    {'LOCATION': 'System', 'LOG_FORMAT': 'eventchannel', 'RECONNECT_TIME': '5'}

]
metadata = [
    {'location': 'Application', 'log_format': 'secure', 'reconnect_time': '5'},
    {'location': 'Security', 'log_format': 'secure', 'reconnect_time': '5'},
    {'location': 'System', 'log_format': 'secure', 'reconnect_time': '5'}
]
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['RECONNECT_TIME']}" for x in parameters]


@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options


def test_command_execution_freq(get_local_internal_options, configure_local_internal_options, get_configuration,
                                configure_environment, restart_logcollector):
    """
    """

    config = get_configuration['metadata']

    # Check event log is been analyzing
    log_callback = logcollector.callback_eventchannel_analyzing(log_format=config[config['location']])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL)

    # Calls function to disable event log

    services.stop_event_log_service()

    log_callback = logcollector.callback_trying_to_reconnect(config['location'], config['reconnect_time'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_EVENTCHANNEL)

    before = str(datetime.now())
    seconds_to_travel = config['frequency'] / 2
    TimeMachine.travel_to_future(timedelta(seconds=seconds_to_travel))
    logger.debug(f"Changing the system clock from {before} to {datetime.now()}")

    log_callback = logcollector.callback_reconect_eventchannel(config['location'], config['reconnect_time'])
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    before = str(datetime.now())
    TimeMachine.travel_to_future(timedelta(seconds=seconds_to_travel))
    logger.debug(f"Changing the system clock from {before} to {datetime.now()}")

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

"""
 import win32evtlog
 h=win32evtlog.OpenEventLog(None, "Application")
flags= win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_
 records=win32evtlog.ReadEventLog(h, flags, 0)
 len(records)
 
 
 records[0].TimeWritten.Format()    

import win32evtlogutil
import win32evtlog
import sys

print("Python {0} on {1}".format(sys.version,sys.platform))

variable = ["x,","y","z"]


App_Name = "Python test"
App_Event_ID = 10001
App_Event_Category = 90
App_Event_Type = win32evtlog.EVENTLOG_WARNING_TYPE
App_Event_Str = ["scanned: {}".format(var) for var in variable]
App_Event_Data= b"xyz"

'''

win32evtlogutil.ReportEvent(ApplicationName, EventID, EventCategory,EventType,Inserts, Data, SID)

'''


win32evtlogutil.ReportEvent(App_Name,App_Event_ID, eventCategory= App_Event_Category,
                                eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE,
                                strings=App_Event_Str,data=App_Event_Data)
"""




def test_command_execution_freq(get_local_internal_options, configure_local_internal_options, get_configuration,
                                configure_environment, restart_logcollector):
    """Check if the Wazuh run correctly with the specified command monitoring option "frequency".

    For this purpose, it is verified that the command has not been executed
    before the period established in this option.

    Args:
        get_local_internal_options (fixture): Get internal configuration.
        configure_local_internal_options (fixture): Set internal configuration.
        get_configuration (fixture): Get configurations from the module.
        configure_environment (fixture): Configure a custom environment for testing.
        restart_logcollector (fixture): Reset log file and start a new monitor.

    Raises:
        TimeoutError: If the command monitoring callback is not generated.
    """

    before = str(datetime.now())
    TimeMachine.travel_to_future(timedelta(seconds=seconds_to_travel))
    logger.debug(f"Changing the system clock from {before} to {datetime.now()}")

    # The command should not be executed in the middle of the command execution cycle.
    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                                error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)


    before = str(datetime.now())
    TimeMachine.travel_to_future(timedelta(seconds=seconds_to_travel))
    logger.debug(f"Changing the system clock from {before} to {datetime.now()}")

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING)

    # Restore the system clock.
    TimeMachine.time_rollback()

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
import sys
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX
import wazuh_testing.logcollector as logcollector
from datetime import datetime

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_age.yaml')

WINDOWS_FOLDER_PATH = r'C:\testing' + '\\'
LINUX_FOLDER_PATH = '/tmp/testing/'

now_date = datetime.now()


if sys.platform == 'win32':
    folder_path = WINDOWS_FOLDER_PATH
    prefix = AGENT_DETECTOR_PREFIX
else:
    folder_path = LINUX_FOLDER_PATH
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX


file_structure = [
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_40s.log",
        "age": 40
    },
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_5m.log",
        "age": 300
    },
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_3h.log",
        "age": 10800
    },
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_5d.log",
        "age": 432000
    },
    {
        "folder_path": f"{folder_path}",
        "filename": "testing_file_300d.log",
        "age": 25920000
    },
]

parameters = [
    {'LOCATION': f'{folder_path}*', 'LOG_FORMAT': 'syslog', 'AGE': '3s'},
    {'LOCATION': f'{folder_path}*', 'LOG_FORMAT': 'syslog', 'AGE': '4000s'},
    {'LOCATION': f'{folder_path}*', 'LOG_FORMAT': 'syslog', 'AGE': '5m'},
]
metadata = [
    {'location': f'{folder_path}*', 'log_format': 'syslog', 'age': '3s'},
    {'location': f'{folder_path}*', 'log_format': 'syslog', 'age': '4000s'},
    {'location': f'{folder_path}*', 'log_format': 'syslog', 'age': '5m'},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['LOCATION'], x['LOG_FORMAT'], x['AGE']}" for x in parameters]


def age_to_seconds(age):
    age_suffix = age[-1]
    if age_suffix == 's':
        factor_rate = 1
    elif age_suffix == 'm':
        factor_rate = 60
    elif age_suffix == 'h':
        factor_rate = 3600
    elif age_suffix == 'd':
        factor_rate = 86400
    return age*factor_rate


@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_files_list():
    """Get configurations from the module."""
    return file_structure


def test_configuration_age(get_files_list, create_file_structure, get_configuration,
                           configure_environment, restart_logcollector):

    cfg = get_configuration['metadata']
    age_seconds = age_to_seconds(cfg['age'])

    for file in file_structure:
        log_callback = logcollector.callback_file_matches_pattern(cfg['location'], file['filename'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                error_message='No testing file detected')
        if age_seconds < file['age']:
            log_callback = logcollector.callback_ignoring_file(file['filename'], prefix=prefix)
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message='Testing file was not ignored')

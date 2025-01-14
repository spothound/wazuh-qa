# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import (LOG_FILE_PATH, callback_audit_event_too_long, regular_file_cud,
                               generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=2)

# Variables

dir_no_recursion = os.path.join(PREFIX, 'test_no_recursion')
dir_recursion_1 = os.path.join(PREFIX, 'test_recursion_1')
dir_recursion_5 = os.path.join(PREFIX, 'test_recursion_5')
dir_recursion_320 = os.path.join(PREFIX, 'test_recursion_320')
subdir = "dir"

dir_no_recursion_space = os.path.join(PREFIX, 'test no recursion')
dir_recursion_1_space = os.path.join(PREFIX, 'test recursion 1')
dir_recursion_5_space = os.path.join(PREFIX, 'test recursion 5')
dir_recursion_320_space = os.path.join(PREFIX, 'test recursion 320')
subdir_space = "dir "

test_directories = [dir_no_recursion, dir_recursion_1, dir_recursion_5, dir_recursion_320, dir_no_recursion_space,
                    dir_recursion_1_space, dir_recursion_5_space, dir_recursion_320_space]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
conf_name = "wazuh_recursion_windows.yaml" if sys.platform == "win32" else "wazuh_recursion.yaml"
configurations_path = os.path.join(test_data_path, conf_name)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

common_params, common_metadata = generate_params(extra_params={'CHECK': {'check_all': 'yes'}})

inode_params, inode_metadata = generate_params(extra_params={'CHECK': {'check_inode': 'no'}})

params = common_params if sys.platform == "win32" else common_params + inode_params
metadata = common_metadata if sys.platform == "win32" else common_metadata + inode_metadata
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# Functions

def recursion_test(dirname, subdirname, recursion_level, timeout=1, edge_limit=2, ignored_levels=1, is_scheduled=False):
    """
    Check that events are generated in the first and last `edge_limit` directory levels in the hierarchy
    dirname/subdirname1/.../subdirname{recursion_level}. It also checks that no events are generated for
    subdirname{recursion_level+ignored_levels}. All directories and subdirectories needed will be created using the info
    provided by parameter.

    Example:
        recursion_level = 10
        edge_limit = 2
        ignored_levels = 2

        dirname = "/testdir"
        subdirname = "subdir"

        With those parameters this function will create files and expect to detect 'added', 'modified' and 'deleted'
        events for the following directories only, as they are the first and last 2 subdirectories within recursion
        level 10:

        /testdir/subdir1
        /testdir/subdir1/subdir2
        /testdir/subdir1/subdir2/subdir3/subdir4/subdir5/subdir6/subdir7/subdir8/subdir9/
        /testdir/subdir1/subdir2/subdir3/subdir4/subdir5/subdir6/subdir7/subdir8/subdir9/subdir10

        As ignored_levels value is 2, this function will also create files on the following directories and ensure that
        no events are raised as they are outside the recursion level specified:

        /testdir/subdir1/subdir2/subdir3/subdir4/subdir5/subdir6/subdir7/subdir8/subdir9/subdir10/subdir11
        /testdir/subdir1/subdir2/subdir3/subdir4/subdir5/subdir6/subdir7/subdir8/subdir9/subdir10/subdir11/subdir12

    This function also takes into account that a very long path will raise a FileNotFound Exception on Windows because
    of its path length limitations. In a similar way, on Linux environments a `Event Too Long` will be raised if the
    path name is too long.

    Parameters
    ----------
    dirname : str
        The path being monitored by syscheck (indicated in the .conf file).
    subdirname : str
        The name of the subdirectories that will be created during the execution for testing purposes.
    recursion_level : int
        Recursion level. Also used as the number of subdirectories to be created and checked for the current test.
    timeout : int
        Max time to wait until an event is raised.
    edge_limit : int
        Number of directories where the test will monitor events.
    ignored_levels : int
        Number of directories exceeding the specified recursion_level to verify events are not raised.
    is_scheduled : bool
        If True the internal date will be modified to trigger scheduled checks by syschecks.
        False if realtime or Whodata.
    """
    path = dirname
    try:
        # Check True (Within the specified recursion level)
        for n in range(recursion_level):
            path = os.path.join(path, subdirname + str(n + 1))
            if ((recursion_level < edge_limit * 2) or
                    (recursion_level >= edge_limit * 2 and n < edge_limit) or
                    (recursion_level >= edge_limit * 2 and n > recursion_level - edge_limit)):
                regular_file_cud(path, wazuh_log_monitor, time_travel=is_scheduled, min_timeout=timeout)

        # Check False (exceeding the specified recursion_level)
        for n in range(recursion_level, recursion_level + ignored_levels):
            path = os.path.join(path, subdirname + str(n + 1))
            regular_file_cud(path, wazuh_log_monitor, time_travel=is_scheduled, min_timeout=timeout,
                             triggers_event=False)

    except TimeoutError:
        timeout_log_monitor = FileMonitor(LOG_FILE_PATH)
        if timeout_log_monitor.start(timeout=5, callback=callback_audit_event_too_long).result():
            pytest.fail("Audit raised 'Event Too Long' message.")
        raise

    except FileNotFoundError as ex:
        MAX_PATH_LENGTH_WINDOWS_ERROR = 206
        if ex.winerror != MAX_PATH_LENGTH_WINDOWS_ERROR:
            raise

    except OSError as ex:
        MAX_PATH_LENGTH_MACOS_ERROR = 63
        MAX_PATH_LENGTH_SOLARIS_ERROR = 78
        if ex.errno not in (MAX_PATH_LENGTH_SOLARIS_ERROR, MAX_PATH_LENGTH_MACOS_ERROR):
            raise


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    return request.param


# Tests

@pytest.mark.parametrize('dirname, subdirname, recursion_level', [
    (dir_no_recursion, subdir, 0),
    (dir_no_recursion_space, subdir_space, 0),
    (dir_recursion_1, subdir, 1),
    (dir_recursion_1_space, subdir_space, 1),
    (dir_recursion_5, subdir, 5),
    (dir_recursion_5_space, subdir_space, 5),
    (dir_recursion_320, subdir, 320),
    (dir_recursion_320_space, subdir_space, 320)
])
def test_recursion_level(dirname, subdirname, recursion_level, get_configuration, configure_environment,
                         restart_syscheckd, wait_for_fim_start):
    """
    Check if files are correctly detected by syscheck with recursion level using scheduled, realtime and whodata
    monitoring.

    Parameters
    ----------
    dirname : str
        The path being monitored by syscheck (indicated in the .conf file).
    subdirname : str
        The name of the subdirectories that will be created during the execution for testing purposes.
    recursion_level : int
        Recursion level. Also used as the number of subdirectories to be created and checked for the current test.
    """
    recursion_test(dirname, subdirname, recursion_level, timeout=global_parameters.default_timeout,
                   is_scheduled=get_configuration['metadata']['fim_mode'] == 'scheduled')

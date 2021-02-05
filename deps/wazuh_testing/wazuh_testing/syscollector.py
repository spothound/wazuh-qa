# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import os
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.services import control_service, check_if_process_is_running

SYSCOLLECTOR_GLOBAL_TIMEOUT = 20
SYSCOLLECTOR_PREFIX = r'wazuh-modulesd:syscollector'

def callback_detect_syscollector_disabled(line):
    msg = rf'(.*){SYSCOLLECTOR_PREFIX}(.*)INFO: Module disabled. Exiting...(.*)'
    match = re.match(msg, line)

    return match is not None


def callback_detect_syscollector_enabled(line):
    msg = r'(.*)Starting Syscollector(.*)'
    match1 = re.match(msg, line)
    msg = r'(.*)INFO: Module disabled. Exiting...(.*)'
    match2 = re.match(msg, line)

    return match1 is not None and match2 is None

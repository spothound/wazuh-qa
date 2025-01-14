#!/usr/bin/env bash

cd /wazuh-qa/deps/wazuh_testing/
python setup.py install

mkdir -p /var/ossec/queue/vulnerabilities/dictionaries/  /var/ossec/etc/ /var/ossec/logs/archives /var/ossec/bin/

echo "" > /var/ossec/queue/vulnerabilities/dictionaries/cpe_helper.json
echo "" > /var/ossec/etc/local_internal_options.conf
echo "" > /var/ossec/logs/archives/archives.log
echo "" > /var/ossec/bin/wazuh-control
echo -e '#!/bin/sh' > /var/ossec/bin/wazuh-control
chmod +x /var/ossec/bin/wazuh-control

cd /wazuh-qa
mkdocs serve -a 0.0.0.0:8080

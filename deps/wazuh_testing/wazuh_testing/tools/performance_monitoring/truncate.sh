#!/bin/bash

echo '' > /var/ossec/logs/alerts/alerts.log
echo '' > /var/ossec/logs/alerts/alerts.json
rm -rf /var/ossec/logs/alerts/2021
echo 'truncated' >> /home/ec2-user/truncate.log

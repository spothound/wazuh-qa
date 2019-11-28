#!/bin/bash

declare -A config_file

config_file=$(find  "$(pwd)" -name '*.conf')

array=($(echo $config_file | tr " " "\n"))

for i in "${array[@]}"
do

  /var/ossec/bin/ossec-control start
  pkill /var/ossec/bin/wazuh-modulesd
  if echo $i | grep -q "agent"; then
    type="agent"
  fi

  if echo $i | grep -q "manager"; then
    type="manager"
  fi

  if echo $i | grep -q "remote"; then
    type="remote"
  fi

  name=($(echo ${i} | cut -d "/" -f 6 | cut -d "." -f 1))
  valgrind --leak-check=full /var/ossec/bin/check_configuration -t ${type} -f ${i} &> valgrind_out_modulesd_config_file_${type}_${name}
  echo -e '\x71\x00\x00\x00{"operation":"GET","type":"request","version":"3.10","component":"check_configuration","data":{"type":"'${type}'","file":"'${i}'"}}' | nc -U /var/ossec/queue/ossec/check_config_sock
  sleep 1
  /var/ossec/bin/ossec-control stop
done
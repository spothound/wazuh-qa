#!/bin/bash

OUTPUT_FILE='tmp.txt'

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <file_path> <stat>"
    exit 1
fi

file=$1
wazuh_stat=$2

if [ ! -f "$file" ]; then
    echo "$file path does not exist."
    exit 1
fi

grep -w $wazuh_stat $file > $OUTPUT_FILE

if [[ $(wc -l < "$file") -eq 0 ]]; then
    echo "Could not find the $wazuh_stat stat"
    exit 1
fi

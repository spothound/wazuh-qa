#!/bin/bash

ansible-playbook -i ansible/hosts ansible/provision_manager.yaml &
ansible-playbook -i ansible/hosts ansible/provision_agent.yaml &

wait < <(jobs -p)
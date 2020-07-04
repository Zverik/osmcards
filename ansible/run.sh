#!/bin/bash
ansible-playbook -i hosts playbook.yml ${1+--start-at-task "$1"}

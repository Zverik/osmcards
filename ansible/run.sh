#!/bin/bash
ansible-playbook -v -i hosts playbook.yml ${1+--start-at-task "$1"}

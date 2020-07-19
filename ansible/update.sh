#!/bin/bash
cd "$(dirname "$0")"
ansible-playbook -v -i hosts playbook.yml --tags osmcards

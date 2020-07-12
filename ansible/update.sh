#!/bin/bash
ansible-playbook -v -i hosts playbook.yml --tags osmcards

#!/bin/bash

echo "Checking for ansible"
if ! command -v ansible &> /dev/null
then
    echo "Ansible is not installed"
fi

echo "Checking /etc/ansible/hosts"
if [ -f /etc/ansible/hosts ]; then
    cat /etc/ansible/hosts
fi

echo "Finding playbooks"
find / -name "*.yml" -type f 2>/dev/null

echo "Finding playbooks with ansible_becom_pass"
find / -name "*.yml" -type f -exec grep -i "ansible_become_pass" {} \;

echo "Finding password in /var/log/syslog"
cat /var/log/syslog | grep -i "password|pass|cred"

echo "Finding password in /var/log/messages"
cat /var/log/messages | grep -i "password|pass|cred"

echo "Finding password in /var/log/auth.log"
cat /var/log/auth.log | grep -i "password|pass|cred"

echo "Finding password in /var/log/secure"
cat /var/log/secure | grep -i "password|pass|cred"

echo "Checking if jfrog is installed"
if ! command -v jfrog &> /dev/null
then
    echo "jfrog is not installed"
fi

echo "Checking for jfrog artifactory"
find /opt/jfrog/artifactory/var/data/access

echo "Checking jfrog console log"
if [ -f /opt/jfrog/artifactory/var/log/console.log ]; then
    sudo cat /opt/jfrog/artifactory/var/log/console.log
fi

echo "Eching for access.backup files exist"
find / -name "access.backup" -type f 2>/dev/null
echo "If they exist, check them for password"

echo "Finding for files with ssh key file permissions"
find / -type f -perms 600 -exec ls -l {} \; 2>/dev/null

echo "Find all ssh_config files that contain ControlMaster or ControlPath"
find / -name "ssh_config" -type f -exec grep -i "ControlMaster|ControlPath|ControlPersist" {} \; 2>/dev/null

echo "Checking for socket files in /opt /tmp /home"
find /opt /tmp /home -type s 2>/dev/null

echo "Checking all running processes for SSH_AUTH_SOCK in environ through /proc"
for i in `find /proc -type f -iname "environ" 2>/dev/null` ; do echo $i ; strings $i 2>/dev/null | grep "SSH_AUTH_SOCK" ; done

echo "Checking for .ssh files in /home"
find /home -name ".ssh" -type d 2>/dev/null



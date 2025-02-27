#!/bin/bash

# Function to check if ansible is installed
check_ansible() {
    echo "===== [Checking for ansible] ==================================================================="
    if ! command -v ansible &> /dev/null; then
        echo "Ansible is not installed"
    fi
}

# Function to check /etc/ansible/hosts
check_ansible_hosts() {
    echo "===== [Checking /etc/ansible/hosts] ==================================================================="
    if [ -f /etc/ansible/hosts ]; then
        cat /etc/ansible/hosts
    fi
}

# Function to find playbooks
find_playbooks() {
    echo "===== [Finding playbooks] ==================================================================="
    find / -name "*.yml" -type f 2>/dev/null
    echo "Finding playbooks with ansible_become_pass"
    find / -name "*.yml" -type f -exec grep -i "ansible_become_pass" {} \; &> /dev/null;
}

# Function to find passwords in log files
find_passwords_in_logs() {
    echo "===== [Finding passwords in log files] ==================================================================="
    for log in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure; do
        echo "Finding password in $log"
        cat "$log" | grep -i "password\|pass\|cred"
    done
}

# Function to check if jfrog is installed
check_jfrog() {
    echo "===== [Checking if jfrog is installed] ==================================================================="
    if ! command -v jfrog &> /dev/null; then
        echo "jfrog is not installed"
    fi
}

# Function to check for jfrog artifactory
check_jfrog_artifactory() {
    echo "===== [Checking for jfrog artifactory] ==================================================================="
    find /opt/jfrog/artifactory/var/data/access
}

# Function to check jfrog console log
check_jfrog_console_log() {
    echo "===== [Checking jfrog console log] ==================================================================="
    if [ -f /opt/jfrog/artifactory/var/log/console.log ]; then
        sudo cat /opt/jfrog/artifactory/var/log/console.log
    fi
}

# Function to check for access.backup files
check_access_backup() {
    echo "===== [Checking for access.backup files] ==================================================================="
    find / -name "access.backup" -type f 2>/dev/null
    echo "If they exist, check them for password"
}

# Function to find files with ssh key file permissions
find_ssh_key_permissions() {
    echo "===== [Finding files with ssh key file permissions] ==================================================================="
    find / -type f -perms 600 -exec ls -l {} \; 2>/dev/null
}

# Function to find ssh_config files with specific options
find_ssh_config() {
    echo "===== [Finding ssh_config files with ControlMaster or ControlPath] ==================================================================="
    find / -name "ssh_config" -type f -exec grep -i "ControlMaster\|ControlPath\|ControlPersist" {} \; 2>/dev/null
}

# Function to check for socket files
check_socket_files() {
    echo "===== [Checking for socket files in /opt /tmp /home] ==================================================================="
    find /opt /tmp /home -type s 2>/dev/null
}

# Function to check running processes for SSH_AUTH_SOCK
check_ssh_auth_sock() {
    echo "===== [Checking all running processes for SSH_AUTH_SOCK in environ through /proc] ==================================================================="
    for i in `find /proc -type f -iname "environ" 2>/dev/null`; do
        echo $i
        strings $i 2>/dev/null | grep "SSH_AUTH_SOCK"
    done
}

# List all files of each user in /home recursive and hidden
list_all_files_home() {
    echo "===== [Listing all files for each user /home] ==================================================================="
    ls -ahlR /home
}

# Function to check for .ssh files in /home
check_ssh_files() {
    echo "===== [Checking for .ssh files in /home] ==================================================================="
    find /home -name ".ssh" -type d 2>/dev/null
}

# Function to check users with a shell that can log in
check_users_with_shell() {
    echo "===== [Checking users with a shell that can log in] ==================================================================="
    awk -F: '($7 !~ /nologin|false/) {print $1, $7}' /etc/passwd
}

# Function to check groups
check_groups() {
    echo "===== [Checking groups] ==================================================================="
    cut -d: -f1 /etc/group
}

# Function to search for keytab files
search_keytab_files() {
    echo "===== [Searching for keytab files] ==================================================================="
    find / -name "*.keytab" -type f 2>/dev/null
}

search_flags() {
    echo "===== [Searching for sensitive files: local.txt, proof.txt, secret.txt] ==================================================================="

    for file in local.txt proof.txt secret.txt; do
        find / -name "$file" -type f 2>/dev/null | while read -r filepath; do
            echo "Found: $filepath"
            echo "Capture it with the following commands:"
            echo "cat $filepath"
            echo "ip a; ifconfig"
            echo "hostname"
            echo "whoami"
            echo "[!!!!!!] MAKE A SCREENSHOT FOR YOUR PROOF!"
            echo "========================================================================================"
        done
    done

}

# Call all functions
check_ansible
check_ansible_hosts
find_playbooks
find_passwords_in_logs
check_jfrog
check_jfrog_artifactory
check_jfrog_console_log
check_access_backup
find_ssh_key_permissions
find_ssh_config
check_socket_files
check_ssh_auth_sock
list_all_files_home
check_ssh_files
check_users_with_shell
check_groups
search_keytab_files
search_flags

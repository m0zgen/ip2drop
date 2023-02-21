#!/bin/bash
# ip2drop ipset / iptables helper

# Sys env / paths / etc
# -------------------------------------------------------------------------------------------\
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd); cd ${SCRIPT_PATH}

# Args and Vars
# ---------------------------------------------------\

IPSET_NAME=$1
IPSET_STATUS=${SCRIPT_PATH}/ipset_status_done

# Checks
# ---------------------------------------------------\

if [[ -z "$1" ]]; then
    echo -e "Please set ipset name. Exit. Bye."
    exit 1
fi

if ! [ -x "$(command -v iptables)" ]; then
  echo 'Error: iptables is not installed.' >&2
  exit 1
fi

# 

setup_firewalld() {
    if [ ! -e $IPSET_STATUS ]
    then
        firewall-cmd --permanent --new-ipset=${IPSET_NAME} --type=hash:ip --option=timeout=60
        firewall-cmd --permanent --add-source=ipset:${IPSET_NAME} --zone=drop
        firewall-cmd --reload
        touch $IPSET_STATUS
    fi
    
}

# Setup ipset
setup_firewalld

STATUS=`iptables -L INPUT -n -v --line-numbers`
if ! echo "$STATUS" | grep -q "${IPSET_NAME}"; then
    echo "Adding banlist to iptables..."
    iptables -v -I INPUT -m set --match-set ${IPSET_NAME} src -j DROP
fi
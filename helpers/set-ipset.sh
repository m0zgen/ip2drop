#!/bin/bash
# ip2drop ipset / iptables helper

IPSET_NAME=$1

if [[ -z "$1" ]]; then
    echo -e "Please set ipset name. Exit. Bye."
    exit 1
fi

if ! [ -x "$(command -v iptables)" ]; then
  echo 'Error: iptables is not installed.' >&2
  exit 1
fi

STATUS=`iptables -L INPUT -n -v --line-numbers`
if ! echo "$STATUS" | grep -q "${IPSET_NAME}"; then
    echo "Adding banlist to iptables..."
    iptables -v -I INPUT -m set --match-set ${IPSET_NAME} src -j DROP
fi
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

if ! [ -x "$(command -v firewall-cmd)" ]; then
    echo 'Error: firewall-cmd is not installed.' >&2
    exit 1
fi
#

# Once operation
rebind_firewalld(){
  firewall-cmd --permanent --remove-source=ipset:${IPSET_NAME} --zone=drop
  firewall-cmd --permanent --delete-ipset=${IPSET_NAME}
  firewall-cmd --reload
  firewall-cmd --permanent --new-ipset=${IPSET_NAME} --type=hash:ip --option=timeout=60  --option=maxelem=524288
  firewall-cmd --permanent --add-source=ipset:${IPSET_NAME} --zone=drop
  firewall-cmd --reload

  local ipset_exists=`ipset -L`

  if echo "$ipset_exists" | grep -iq "${IPSET_NAME}" ;
  then
      touch $IPSET_STATUS
      exit 0
  else
      exit 1
  fi

}

# Setup ipset
rebind_firewalld

STATUS=`iptables -L INPUT -n -v --line-numbers`

if echo "$STATUS" | grep -iq "${IPSET_NAME}" ;
then
    if [[ ! -f ../.prod ]]; then
        echo "Info: ${IPSET_NAME} ipset - Ok."
    fi
    exit 0
else
    iptables -v -I INPUT -m set --match-set "${IPSET_NAME}" src -j DROP >/dev/null 2>&1
    exit 0
fi

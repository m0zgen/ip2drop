#!/bin/bash
# ip2drop ipset find existing ip from upload file

# Get script path
# shellcheck disable=SC2164
# shellcheck disable=SC2046
# shellcheck disable=SC2006
SCRIPT_PATH="$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)"; cd "${SCRIPT_PATH}"


# List files in directory
# shellcheck disable=SC2045
for file in $(ls -1 "../upload"); do
  # Check is file empty
  if [ -s "../upload/${file}" ]; then
    # Check is file not empty
    # shellcheck disable=SC2002
    echo "File ${file} is not empty. Processing..."
    # Enumerate file lines
    while read -r line; do
      # Check is ipset exists
      if `ipset -L ip2drop | grep -q "${line}"`; then
        echo "IP ${line} exists in ipset"
      else
        echo "IP ${line} not exists in ipset"
      fi
    done < "../upload/${file}"
  else
    echo "File ${file} is empty"
  fi
done


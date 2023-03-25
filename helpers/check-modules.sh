#!/bin/bash
# ip2drop ipset / iptables helper
# Thx: https://askubuntu.com/questions/588390/how-do-i-check-whether-a-module-is-installed-in-python-and-install-it-if-needed

# Sys env / paths / etc
# -------------------------------------------------------------------------------------------\
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd); cd ${SCRIPT_PATH}

PACKAGES_STATUS=${SCRIPT_PATH}/packages_status_done

# Check is current user is root
isRoot() {
  if [ $(id -u) -ne 0 ]; then
    echo "You must be root user to continue"
    exit 1
  fi
  RID=$(id -u root 2>/dev/null)
  if [ $? -ne 0 ]; then
    echo "User root no found. You should create it to continue"
    exit 1
  fi
  if [ $RID -ne 0 ]; then
    echo "User root UID not equals 0. User root must have UID 0"
    exit 1
  fi
}

# Checks supporting distros
checkDistro() {
    # Checking distro
    if [ -e /etc/centos-release ]; then
        DISTRO=`cat /etc/redhat-release | awk '{print $1,$4}'`
        RPM=1
    elif [ -e /etc/fedora-release ]; then
        DISTRO=`cat /etc/fedora-release | awk '{print ($1,$3~/^[0-9]/?$3:$4)}'`
        RPM=2
    elif [ -e /etc/os-release ]; then
        DISTRO=`lsb_release -d | awk -F"\t" '{print $2}'`
        RPM=0
        DEB=1
    else
        Error "Your distribution is not supported (yet)"
        exit 1
    fi
}

# Packages
# ---------------------------------------------------\

packages=(
    ipset
    python3
    python3-pip
    python3-psutil
    python3-requests
)

# Checks
check_packages() {

    if [ ! -e $PACKAGES_STATUS ]; then

        for package in "${packages[@]}"; do

            if ! [ -x "$(command -v "${package}")" ]; then
                echo "Error: ${package} is not installed."
                # TODO: Install packages. Yes / No answer
                apt -y install ${package}
            fi

        done

        touch $PACKAGES_STATUS
    fi

}

# for module in "${pymodules[@]}"; do
#     if python3 -c "import pkgutil; exit(1 if pkgutil.find_loader(\"$module\") else 0)"; then
#         pip3 install --user "$module"
#     fi
# done

isRoot
checkDistro
if [[ "$RPM" -eq "1" ]]; then
    echo "CentOS detected... Please install packages manually."
    # centos
elif [[ "$RPM" -eq "2" ]]; then
    echo "Fedora detected... Please install packages manually."
    # fedora
elif [[ "$DEB" -eq "1" ]]; then
    # echo "Debian detected..."
    check_packages
else
    echo "Unknown distro. Exit."
    exit 1
fi
import datetime
import os
import sys
import logging
import subprocess
from pathlib import Path
from sys import platform
import socket

sys.path.append(str(Path(sys.argv[0]).absolute().parent.parent))
from . import var

# System log
# Detect system/platform
if platform == "linux" or platform == "linux2":
    SYSTEM_LOG = '/var/log/ip2drop.log'
elif platform == "darwin":
    SYSTEM_LOG = os.path.join(var.EXPORTED_LOGS_DIR, 'ip2drop-script.log')
elif platform == "win32":
    print('Platform not supported. Exit. Bye.')
    exit(1)

# Logging
logging.basicConfig(filename=SYSTEM_LOG,
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%d-%m-%Y %H-%M-%S',
                    level=logging.DEBUG)


# Logger messages
# TODO: Add -v, --verbose as DEBUG mode
def log_debug(msg):
    logging.debug(msg)


def log_info(msg):
    logging.info(msg)


def log_warn(msg):
    logging.warning(msg)


def log_err(msg):
    logging.error(msg)


def log_crit(msg):
    logging.critical(msg)


def msg_info(msg):
    log_info(msg)
    print(msg)


# Command operators
def bash_command(cmd):
    subprocess.Popen(cmd, shell=True, executable='/bin/bash')


def bash_cmd(cmd):
    subprocess.Popen(['/bin/bash', '-c', cmd])
    # print(f'CMD: {cmd}')


# Expiremental

# Ad id to filename, like as dato for log rotate
# Ref: https://stackoverflow.com/questions/37487758/how-to-add-an-id-to-filename-before-extension
def append_id(filename):
    name, ext = os.path.splitext(filename)
    result = "{name}_{uid}{ext}".format(name=name, uid=var.TODAY.strftime("%d_%m_%Y"), ext=ext)
    # msg_info(f'Result: {result}')
    return result

def get_hostname():
    return socket.getfqdn()
    # print(os.uname().nodename)
    # print(socket.gethostname())

def check_dir(dest):
    is_exist = os.path.exists(dest)
    if not is_exist:
        # Create a new directory because it does not exist
        os.makedirs(dest)
        msg_info(f'Log catalog: {dest} created. Done.')


def check_file(file):
    # Create the file if it does not exist
    if not os.path.exists(file):
        open(file, 'w').close()
        msg_info(f'Log file: {file} created. Done.')


def truncate_file(file):
    with open(file, 'r+') as file:
        file.truncate(0)


def increment(number):
    number += 1
    return number


def get_current_date():
    return datetime.date.today()


def get_current_time():
    return datetime.datetime.now()

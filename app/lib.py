import os
import sqlite3
import sys
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from sys import platform
import socket
import getpass

import requests

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


def get_username():
    return getpass.getuser()


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


def append_to_file(file, line):
    with open(file, 'a') as file:
        file.write(f'{line}\n')
        # file.close()


def check_http_200(url):
    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            # print("OK")
            return True
        else:
            # print("False")
            return False
    except requests.exceptions.InvalidSchema:
        print("Host not available <InvalidSchema>: ", url)
        return False
    except requests.exceptions.ConnectionError:
        print("Host not available <ConnectionError>: ", url)
        return False


def truncate_file(file):
    with open(file, 'r+') as file:
        file.truncate(0)


def increment(number):
    number += 1
    return number


def get_current_date():
    return datetime.date.today()


def get_current_time():
    return datetime.now()


# Connect to sqlite3
# ------------------------------------------------------------------------------------------------------/
def connect_db():
    try:
        conn = sqlite3.connect(var.DROP_DB)
        return conn
    except sqlite3.Error as e:
        print(e)
    return None


# Select drop_date from table ip2drop by ip
# ------------------------------------------------------------------------------------------------------/
def get_drop_date_from_ip(ip):
    fetched_date = ""
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT drop_date FROM ip2drop WHERE ip = ?", (ip,))
    # print(c.fetchall())

    # Iterate over list c.fetchall()
    # ---------------------------------/
    for row in c.fetchall():
        fetched_date = row[0]
    return fetched_date


# Select timeout from table ip2drop by ip
# ------------------------------------------------------------------------------------------------------/
def get_timeout_from_ip(ip):
    fetched_date = ""
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT timeout FROM ip2drop WHERE ip = ?", (ip,))
    # print(c.fetchall())
    for row in c.fetchall():
        fetched_date = row[0]
    return fetched_date


# Increment record to table ip2drop by ip
# Increment count by +1
# ------------------------------------------------------------------------------------------------------/
def increment_by_ip(ip):
    conn = connect_db()
    c = conn.cursor()
    c.execute("""UPDATE ip2drop SET COUNT = COUNT + 1 WHERE ip = ?""", (ip,))
    conn.commit()


# Check date less than or more than current date
# ------------------------------------------------------------------------------------------------------/
def check_date(ip, drop_date, timeout):
    current_date = datetime.now()
    bool_status = False

    # Convert list to string
    # ---------------------------------/
    drop_date = str(drop_date)
    timeout = str(timeout)
    # Convert string to datetime
    # ---------------------------------/
    drop_date_as_dt = datetime.strptime(drop_date, var.DATETIME_DEFAULT_FORMAT)
    timeout_as_dt = datetime.strptime(timeout, var.DATETIME_DEFAULT_FORMAT)

    # Time delta
    # ------------------------------------------------------------------------------------------------------/

    # String to datetime
    timeout = datetime.strptime(timeout, var.DATETIME_DEFAULT_FORMAT)
    delta = timeout - current_date

    # print(delta.days)
    # print(delta.seconds)
    # print(delta.microseconds)
    # print(delta.total_seconds())

    log_info(f'Dropped: {drop_date}, Timeout: {timeout}, Current: {current_date}')

    if current_date > timeout_as_dt:
        msg_info(f'IP {ip} need ban again. Overdue: {str(delta)}')
        log_info(f'IP {ip} need ban again. Overdue: {str(delta)}')
        bool_status = True
    else:
        # print("Timeout less than current date. No need action. Left: " + str(delta))
        # msg_info(f'{ip} - Timeout is greater than current date. No need action. Left: {str(delta)}')
        log_info(f'{ip} - Timeout is greater than current date. No need action. Left: {str(delta)}')

    return bool_status

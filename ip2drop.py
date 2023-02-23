#!/usr/bin/env python3
# Author: Yevgeniy Goncharov, https://lab.sys-adm.in
# Find malicious IP addresses through executed command and send it's to firewalld drop zone for relaxing)

# Imports

import os
import re
import argparse
import ipaddress
import datetime
import logging
import subprocess
from subprocess import Popen, PIPE
import sqlite3
import configparser
import shlex
from collections import Counter
from sys import platform

# Init Section
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Relative paths
RELATIVE_SRC_DIR = "src/"
RELATIVE_DB_DIR = "db/"
RELATIVE_LOGS_DIR = "logs/"
RELATIVE_CONF_DIR = "conf.d/"
RELATIVE_HELPERS_DIR = "helpers/"

# Load CONFIG
CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(BASE_DIR, 'config.ini'))

# Load Options
IP_TIMEOUT = CONFIG['DEFAULT'].getint('IP_TIMEOUT')
IP_THRESHOLD = CONFIG['DEFAULT'].getint('IP_THRESHOLD')
# EXPORT_COMMAND = CONFIG['DEFAULT']['EXPORT_COMMAND']
EXPORT_COMMAND = "/usr/bin/journalctl -u ssh -S today --no-tail | grep 'Failed password'"
IP_EXCLUDES = CONFIG['DEFAULT']['IP_EXCLUDES']
IPSET_NAME = CONFIG['DEFAULT']['IPSET_NAME']
IPSET_ENABLED = CONFIG['DEFAULT'].getboolean('IPSET_ENABLED')

# print(f'TIMEOUT: {IP_TIMEOUT}, COMMAND: {EXPORT_COMMAND}, ENABLED: {IPSET_ENABLED}')

# Set Working Paths
DB_DIR = os.path.join(BASE_DIR, RELATIVE_DB_DIR)
SRC_DIR = os.path.join(BASE_DIR, RELATIVE_SRC_DIR)
CONF_DIR = os.path.join(BASE_DIR, RELATIVE_CONF_DIR)
HELPERS_DIR = os.path.join(BASE_DIR, RELATIVE_HELPERS_DIR)
EXPORTED_LOGS_DIR = os.path.join(BASE_DIR, RELATIVE_LOGS_DIR)

# Default log file name
CTL_LOG_FILE = "ip2drop.log"

# Database Schema
DROP_DB = os.path.join(DB_DIR, 'db.sqlite3')
DROP_DB_SCHEMA = os.path.join(SRC_DIR, 'db_schema.sql')
ARG_DEFAULT_MSG = "Drop IP Information"

# Datetime Format for Journalctl exported logs
DATETIME_DEFAULT_FORMAT = '%Y-%m-%d %H:%M:%S.%f'
TODAY = datetime.date.today()

# Detect system/platform
if platform == "linux" or platform == "linux2":
    SYSTEM_LOG = '/var/log/ip2drop.log'
elif platform == "darwin":
    SYSTEM_LOG = os.path.join(EXPORTED_LOGS_DIR, 'ip2drop-script.log')
elif platform == "win32":
    print('Platform not supported. Exit. Bye.')
    exit(1)

# Logger
# TODO: Add -v, --verbose as DEBUG mode
logging.basicConfig(filename=SYSTEM_LOG,
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%d-%m-%Y %H-%M-%S',
                    level=logging.DEBUG)


# Logger messages
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


# Actions

# FS Operations

def bash_command(cmd):
    subprocess.Popen(cmd, shell=True, executable='/bin/bash')


def bash_cmd(cmd):
    subprocess.Popen(['/bin/bash', '-c', cmd])
    # print(f'CMD: {cmd}')



def check_dir(dest):
    is_exist = os.path.exists(dest)
    if not is_exist:
        # Create a new directory because it does not exist
        os.makedirs(dest)
        print(f'Log catalog: {dest} created. Done.')


def check_file(file):
    # Create the file if it does not exist
    if not os.path.exists(file):
        open(file, 'w').close()
        print(f'Log file: {file} created. Done.')


def check_start_end(current_timeout, time_difference, log):
    # Timing processes
    log_time_format = '%H:%M:%S'

    # start_cheking_time = datetime.datetime.strptime(current_timeout, '%H:%M:%S').time()
    end_checking_time = get_current_time().strftime('%H:%M:%S')

    datetime_obj = datetime.datetime.strptime(current_timeout,
                                              DATETIME_DEFAULT_FORMAT)

    time = datetime_obj.time()
    time = str(time).split('.')[0]

    print(f'Start time: {time}, End time: {end_checking_time}')

    print(
        f'Current timeout: {current_timeout}, Timeout: {time_difference}')

    # stat_count = get_drop_count(ip)
    # print(f'Count: {stat_count}')

    # TODO: Get current 'status' and then +1 (get_drop_status)
    # TODO: Get undropTime if
    # TODO: Get current time and expire time

    # print(f'Timeout {current_timeout}, Count: {current_count}')


# DB Operations

# TODO: Proccess db operation to def
# Add db.sql exists testing

def create_db_schema():
    try:
        # https://pyneng.readthedocs.io/en/latest/book/25_db/example_sqlite.html
        conn = sqlite3.connect(DROP_DB)

        print(f'Checking {DROP_DB} schema...')
        with open(DROP_DB_SCHEMA, 'r') as f:
            schema = f.read()
            conn.executescript(schema)
        # print("Done")
        # conn.close()
    except sqlite3.Error as error:
        print("Error while creating a sqlite table", error)
    finally:
        if conn:
            conn.close()
            print(f'Checking {DROP_DB} schema: Done.')


def add_drop_ip(ip, ip_int, status, count, timeout, date_added, group):
    conn = sqlite3.connect(DROP_DB)
    cursor = conn.cursor()
    params = (ip, ip_int, status, count, timeout, date_added, group)
    cursor.execute("INSERT INTO ip2drop VALUES (?,?,?,?,?,?,?)", params)
    conn.commit()
    print('Drop Entry Created Successful')
    conn.close()


def get_timeout(ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    count = cur.execute("SELECT timeout FROM ip2drop WHERE IP LIKE :IP", {'IP': ip})
    result, = count.fetchone()
    # print(result)
    conn.close()
    return result


# Status counting
def get_drop_count(ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    count = cur.execute("SELECT count FROM ip2drop WHERE IP LIKE :IP", {'IP': ip})
    result, = count.fetchone()
    # print(result)
    conn.close()
    return result


def update_drop_count(count, ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    # cur.execute('''UPDATE ip2drop SET status = ? WHERE ip = ?''', (status, ip))
    cur.execute("""UPDATE ip2drop SET COUNT = :COUNT WHERE IP =:IP """, {'STATUS': count, 'IP': ip})
    conn.commit()
    print("Update Status Successful")
    conn.close()


def get_drop_status(ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    stat = cur.execute("SELECT status FROM ip2drop WHERE IP LIKE :IP", {'IP': ip})
    result, = stat.fetchone()
    # print(result)
    conn.close()
    return result


def update_drop_status(status, ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    # cur.execute('''UPDATE ip2drop SET status = ? WHERE ip = ?''', (status, ip))
    cur.execute("""UPDATE ip2drop SET STATUS = :STATUS WHERE IP =:IP """, {'STATUS': status, 'IP': ip})
    conn.commit()
    print("Update Status Successful")
    conn.close()


# TODO: Checking already banned

def delete_dropped_ip(ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    cur.execute("""DELETE FROM ip2drop WHERE IP =:IP """, {'IP': ip})
    conn.commit()
    print(f'IP Deletion Successful: {ip}')
    conn.close()


# TODO: Get info from dropped IP
def get_drop_ip(ip):
    conn = sqlite3.connect(DROP_DB)
    response = conn.execute("SELECT EXISTS(SELECT 1 FROM ip2drop WHERE ip=?)", (ip,))
    fetched = response.fetchone()[0]
    if fetched == 1:
        print(fetched)
    else:
        print("Not found")
    conn.close()

    # if cur.fetchone()[1] == ip:
    #     print('LogIn Successful') 


def ip_exist(ip):
    conn = sqlite3.connect(DROP_DB)
    response = conn.execute("SELECT EXISTS(SELECT 1 FROM ip2drop WHERE ip=?)", (ip,))
    fetched = response.fetchone()[0]
    if fetched == 1:
        # print("Exist")
        conn.close()
        return True
    else:
        # print("Does not exist")
        conn.close()
        return False


def print_db_entries():
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    for row in cur.execute('SELECT * FROM ip2drop;'):
        print(row)
    conn.close()


# Firewall Operations
def add_ip_to_firewalld(ip):
    os.system("firewall-cmd --zone=drop --add-source=" + ip)
    log_warn(f'{ip} added to firewalld.')


def remove_ip_from_firewall(ip):
    os.system("firewall-cmd --zone=drop --remove-source=" + ip)
    log_warn(f'{ip} removed from firewalld.')


# Log parsing
def get_ip(line):
    ip = line.split(" ")[9]
    return ip


def extract_ip(line):
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ip = pattern.search(line)[0]
    return ip


# Services
def increment(number):
    number += 1
    return number


def get_current_date():
    return datetime.date.today()


def get_current_time():
    return datetime.datetime.now()


# Ref: https://stackoverflow.com/questions/37487758/how-to-add-an-id-to-filename-before-extension
def append_id(filename):
    name, ext = os.path.splitext(filename)
    result = "{name}_{uid}{ext}".format(name=name, uid=TODAY.strftime("%d_%m_%Y"), ext=ext)
    # msg_info(f'Result: {result}')
    return result


def delete_ip(ip):
    if ip_exist(ip):
        print(f'IP: {ip} will be deleted')
        delete_dropped_ip(ip)
        remove_ip_from_firewall(ip)
        log_info(f'IP: {ip} deleted from DB: {DROP_DB}')
    else:
        print(f'IP: {ip} not exist in DB')
        log_info(f'IP: {ip} not exist in DB')


def export_log(command, destination):
    os.system(command + ' > ' + destination)
    # bash_cmd(command + ' > ' + destination)
    # cmd_line = f'{command} > {destination}'
    # cmd = shlex.split(cmd_line)
    # print(f'{cmd}')
    # bash_command(cmd)


# def validate_ip(ip):
#     # https://stackoverflow.com/questions/3462784/check-if-a-string-matches-an-ip-address-pattern-in-python
#     iptools.ipv4.validate_ip(ip) #returns bool
#     # iptools.ipv6.validate_ip(ipv6) #returns bool
#     # TODO: need to add validation logic

# General
def get_log(log, threshold, excludes, showstat):
    msg_info(f'Info: Processing log: {log}')
    found_count = 0

    with open(log, "r") as f:
        ips = Counter(extract_ip(line) for line in f)
        exclude_from_check = excludes.split(' ')
        # print(exclude_from_check)

        for ip, count in ips.items():
            # print(ip, '->', count)

            # Checking excludes list
            if ip in exclude_from_check:
                msg_info(f'Info: Found Ignored IP: {ip} with count: {count}')
                found_count = increment(found_count)

            # Checking threshold
            elif count >= threshold:
                int_ip = int(ipaddress.IPv4Address(ip))
                # IP from int converter
                from_int = ipaddress.IPv4Address(int_ip)
                # print(from_int)
                found_count = increment(found_count)

                # Show threshold statistic without drop (arg: -s)
                if showstat:
                    print(f'Warning: Found - {ip} -> Threshold: {count} (Show stat found without drop)')
                    log_warn(f'Action without drop. Found: {ip} -> Threshold: {count}')
                    found_count = increment(found_count)

                else:
                    # TODO: Need to remove this section
                    print(f'\nAction: Drop: {ip} -> Threshold: {count}')
                    # Drop time
                    current_date = get_current_time()
                    # Drop end
                    undrop_date = current_date + datetime.timedelta(seconds=IP_TIMEOUT)
                    # Ban
                    add_ip_to_firewalld(ip)

                    # IN DEVELOP:
                    if ip_exist(ip):

                        current_timeout = get_timeout(ip)
                        current_count = get_drop_count(ip)

                        # Format: 2023-02-11 18:27:50.192957
                        time_difference = current_date - datetime.datetime.strptime(current_timeout,
                                                                                    DATETIME_DEFAULT_FORMAT)
                        total_seconds = time_difference.total_seconds()
                        # print(f'Timeout: {time_difference}')
                        # print(f'Total seconds: {total_seconds}')
                        # check_start_end(current_count, time_difference, log)

                        # TODO: Add and update drop counts

                        print(f'Info: IP exist in Drop DB: {ip} till to: {current_timeout}')
                        log_info(f'IP exist in Drop DB: {ip} till to: {current_timeout}')

                        update_drop_status(2, ip)

                    else:
                        # Add to DB
                        add_drop_ip(ip, int_ip, 1, 1, undrop_date, current_date, 'testing')
                        log_info(f'Add drop IP to DB: {ip}')
                        # print(f'Action: Drop: {ip} -> Threshold: {count}')
                        # os.system("firewall-cmd --zone=drop --add-source=" + ip)
                    found_count = increment(found_count)
            # else:
            #     print(f'Attack with threshold ({IP_THRESHOLD}) conditions  not detected.')
    if found_count == 0:
        log_info(f'Info: Thread does not found.')
        print(f'Info: Thread does not found.')

    # print(f'Found count: {found_count}')


# Arguments parser
def arg_parse():
    parser = argparse.ArgumentParser(description=ARG_DEFAULT_MSG)
    parser.add_argument('-c', '--command', dest='command', type=str, help='Command for execute', default=EXPORT_COMMAND)
    parser.add_argument('-l', '--logfile', dest='logfile', type=str, help='Log file name', default=CTL_LOG_FILE)
    parser.add_argument('-t', '--threshold', dest='threshold', type=int, help='Ban time', default=IP_THRESHOLD)
    parser.add_argument('-d', '--delete', dest='delete', type=str, help='Delete IP from database')
    parser.add_argument('-e', '--excludes', dest='excludes', help="Excludes IP list with space separated",
                        default=IP_EXCLUDES)
    parser.add_argument('-s', '--stat', action='store_true', help='Show status without drop',
                        default=False)
    parser.add_argument('-p', '--print', action='store_true', help='Print data drom DB',
                        default=False)

    # args = parser.parse_args()
    return parser.parse_args()


# Main
def main():
    args = arg_parse()

    # Dirty step
    # TODO: Need to make more beauty)
    if IPSET_ENABLED:
        subprocess.run([HELPERS_DIR + "set-ipset.sh",
                IPSET_NAME])

    # Create db if not exists
    if not os.path.exists(DB_DIR):
        check_dir(DB_DIR)
        create_db_schema()

    # Log file for command processing
    # today_log = append_id(args.logfile)
    # ctl_log = os.path.join(EXPORTED_LOGS_DIR, today_log)
    ctl_log = os.path.join(EXPORTED_LOGS_DIR, args.logfile)

    # Checking & creating needed dirs and files
    check_dir(EXPORTED_LOGS_DIR)
    check_file(ctl_log)

    if args.stat:
        print('Mode: Show statistics without actions')

    if args.print:
        print('Mode: Print DB records')
        print_db_entries()
        exit(0)

    if args.delete is not None:
        delete_ip(args.delete)
        exit(0)

    # if args.delete:
    #     print('Delete IP from DB')
    #     exit(0)

    # print(f'Using command: {args.command}')
    # print(f'Checking threshold: {args.threshold}')
    log_info(f'ip2drop started with params:')
    log_info(f'Command: {args.command} Log: {ctl_log} Threshold {args.threshold} Stat: {args.stat}')

    # Execute command with export results to log
    export_log(args.command, ctl_log)
    # Exported log processing
    get_log(ctl_log, args.threshold, args.excludes, args.stat)


# Init starter
if __name__ == "__main__":
    raise SystemExit(main())

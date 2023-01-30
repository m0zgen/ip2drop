#!/usr/bin/env python3
# Author: Yevgeniy Goncharov, https://lab.sys-adm.in
# Find malicious IP addresses through executed command and send it's to firewalld drop zone for relaxing)

## Imports

import os
import re
import sqlite3
import ipaddress
from collections import Counter
import datetime
import argparse
import logging

## Vars

IP_TIMEOUT = 10
IP_THRESHOLD = 150
CTL_LOG_FILE = "ip2drop.log"
CTL_LOG_DIR = f'{os.getcwd()}/log'
EXPORT_COMMAND = "journalctl -u ssh -S today --no-tail | grep 'Failed password'"
IP_EXCLUDES = "127.0.0.1 1.1.1.1 "

DROP_DB = f'{os.getcwd()}/db.sql'
DROP_DB_SCHEMA = f'{os.getcwd()}/db_schema.sql'
ARG_DEFAULT_MSG = "Drop IP Information"

## Init Logger

# TODO: Add -v, --verbose as DEBUG mode
logging.basicConfig(filename = '/var/log/ip2drop.log',
                filemode='a',
                format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                datefmt='%d-%m-%Y %H-%M-%S',
                level=logging.DEBUG)

def _debug(msg):
    logging.debug(msg)

def _info(msg):
    logging.info(msg)

def _warn(msg):
    logging.warning(msg)

def _err(msg):
    logging.error(msg)

def _crit(msg):
    logging.critical(msg)


## Actions

## FS Operations

def check_dir(dest):
    isExist = os.path.exists(dest)
    if not isExist:
        # Create a new directory because it does not exist
        os.makedirs(dest)
        print(f'Log catalog: {dest} created. Done.')


def check_file(file):
    # Create the file if it does not exist
    if not os.path.exists(file):
        open(file, 'w').close()
        print(f'Log file: {file} created. Done.')


## DB Operations

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
        conn.close()
    except sqlite3.Error as error:
        print("Error while creating a sqlite table", error)
    finally:
        if conn:
            conn.close()
            print(f'Checking {DROP_DB} schema: Done.')


def add_drop_ip(ip, ip_int, status, timeout, date_added, group):
    conn = sqlite3.connect(DROP_DB)
    cursor = conn.cursor()
    params = (ip, ip_int, status, timeout, date_added, group)
    cursor.execute("INSERT INTO ip2drop VALUES (?,?,?,?,?,?)", params)
    conn.commit()
    print('Drop Entry Created Successful')
    conn.close()


# Status counting
def update_drop_status(status, ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    # cur.execute('''UPDATE ip2drop SET status = ? WHERE ip = ?''', (status, ip))
    cur.execute("""UPDATE ip2drop SET STATUS = :STATUS WHERE IP =:IP """, {'STATUS': status, 'IP': ip})
    conn.commit()
    print("Update Status Successful")
    conn.close()


## TODO: Checking already banned

def delete_dropped_ip(ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    cur.execute("""DELETE FROM ip2drop WHERE IP =:IP """, {'IP': ip})
    conn.commit()
    print(f'IP Deletion Successful: {ip}')
    conn.close()


# TODO: Get info dor dropped IP
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


## Firewall Operations

def remove_ip_from_firewall(ip):
    os.system("firewall-cmd --zone=drop --remove-source=" + ip)
    _warn(f'{ip} removed from firewalld.')


def get_ip(line):
    ip = line.split(" ")[9]
    return ip


def extract_ip(line):
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ip = pattern.search(line)[0]
    return ip


# def validate_ip(ip):
#     # https://stackoverflow.com/questions/3462784/check-if-a-string-matches-an-ip-address-pattern-in-python
#     iptools.ipv4.validate_ip(ip) #returns bool
#     # iptools.ipv6.validate_ip(ipv6) #returns bool
#     # TODO: need to add validation logic

def delete_ip(ip):
    if ip_exist(ip):
        print(f'IP: {ip} will be deleted')
        delete_dropped_ip(ip)
        remove_ip_from_firewall(ip)
        _info(f'IP: {ip} deleted from DB: { DROP_DB }')
    else:
        print(f'IP: {ip} not exist in DB')
        _info(f'IP: {ip} not exist in DB')


def export_log(command, desctination):
    os.system(command + ' > ' + desctination)


def get_log(log, threshold, excludes, showstat):
    print(f'Info: Processing log: {log}')
    _info(f'Processing log: {log}')

    with open(log, "r") as f:
        ips = Counter(extract_ip(line) for line in f)

        exclude_from_check = excludes.split(' ')
        # print(exclude_from_check)

        for ip, count in ips.items():
            # print(ip, '->', count)
            if ip in exclude_from_check:
                print(f'Info: Found Ignored IP: {ip}')
                _info(f'Found Ignored IP: {ip}')

            elif count >= threshold:
                int_ip = int(ipaddress.IPv4Address(ip))
                # print(int_ip)

                frop_int = ipaddress.IPv4Address(int_ip)
                # print(frop_int)
                if showstat:
                    print(f'Show stat found: {ip} -> Threshold: {count}')
                    _info(f'Action without drop. Found: {ip} -> Threshold: {count}')
                    # TODO: need to coding
                else:

                    # TODO: Beed to remove this section
                    print(f'Action: Drop: {ip} -> Threshold: {count}')
                    os.system("firewall-cmd --zone=drop --add-source=" + ip)
                    _warn(f'{ip} send to drop zone')
                    # Drop time
                    currentDate = datetime.datetime.now()
                    # Drop end
                    undropDate = currentDate + datetime.timedelta(seconds=IP_TIMEOUT)

                    # Check true
                    if ip_exist(ip):
                        print(f'Info: IP exist in Drop DB: {ip}')
                        _info(f'IP exist in Drop DB: {ip}')
                        # TODO: Get current 'status' and then +1
                        update_drop_status(11, ip)
                    else:
                        add_drop_ip(ip, int_ip, 1, undropDate, currentDate, 'testing')
                        _info(f'Add drop IP to DB: {ip}')
                        # print(f'Action: Drop: {ip} -> Threshold: {count}')
                        # os.system("firewall-cmd --zone=drop --add-source=" + ip)
            # else:
            #     print(f'Attack with threshold ({IP_THRESHOLD}) conditions  not detected.')


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


def main():
    args = arg_parse()

    if not os.path.exists(DROP_DB):
        create_db_schema()

    ctl_log = f'{CTL_LOG_DIR}/{args.logfile}'

    check_dir(CTL_LOG_DIR)
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
    _info(f'ip2drop started with params:')
    _info(f'Command: { args.command } Log: { ctl_log } Threshold { args.threshold } Stat: { args.stat }')

    export_log(args.command, ctl_log)
    get_log(ctl_log, args.threshold, args.excludes, args.stat)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Author: Yevgeniy Goncharov, https://lab.sys-adm.in
# Find malicious IP addresses through executed command and send it's to firewalld drop zone for relaxing)

import os
import re
import sqlite3
import ipaddress
from collections import Counter
import datetime
import argparse

ip_timeoit = 10
ip_threshold = 150
ctl_log_file = "ip2drop.log"
ctl_log_dir = f'{os.getcwd()}/log'
export_command = "journalctl -u ssh -S today --no-tail | grep 'Failed password'"
ip_excludes = "127.0.0.1 1.1.1.1 "

drop_db = "db.sql"
drop_db_schema = "db_schema.sql"
arf_default_msg = "Drop IP Information"

## 

# TODO: Proccess db operation to def
# Add db.sql exists testing

try:
    # https://pyneng.readthedocs.io/en/latest/book/25_db/example_sqlite.html
    conn = sqlite3.connect(drop_db)

    print(f'Checking {drop_db} schema...')
    with open(drop_db_schema, 'r') as f:
        schema = f.read()
        conn.executescript(schema)
    # print("Done")
    conn.close()
except sqlite3.Error as error:
    print("Error while creating a sqlite table", error)
finally:
    if conn:
        conn.close()
        print(f'Checking {drop_db} schema: Done.')


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

def add_drop_ip(ip, ip_int, status, timeout, date_added, group):
    conn = sqlite3.connect(drop_db)
    cursor = conn.cursor()
    params = (ip, ip_int, status, timeout, date_added, group)
    cursor.execute("INSERT INTO ip2drop VALUES (?,?,?,?,?,?)", params)
    conn.commit()
    print('Drop Entry Created Successful')
    conn.close()


def update_drop_status(ip, status):
    conn = sqlite3.connect('drop_db')
    cur = conn.cursor()
    # status = input("Enter status: ")
    cur.execute("""UPDATE ip2drop SET STATUS = :STATUS WHERE IP =:IP """,{'STATUS':status,'IP':ip})
    conn.commit()
    print("Update Status Successful")
    conn.close()

## TODO: Checking already banned

def delete_dropped_ip(ip):
    conn = sqlite3.connect(drop_db)
    cur = conn.cursor()
    cur.execute("""DELETE FROM ip2drop WHERE IP =:IP """,{'IP':ip})
    conn.commit()
    print(f'IP Deletion Successful: {ip}')
    conn.close()


def get_drop_ip(ip):
    conn = sqlite3.connect(drop_db)
    cur = conn.cursor()
    cur.execute("SELECT * FROM ip2drop WHERE IP =:IP", {'IP': ip})
    status = cur.fetchone()
    print(f'Status {status}')

    fetched = cur.fetchone()[0]
    if fetched == 1:
        print("Exist")
        return True
    else:
        print("Does not exist")
        return False

    # if cur.fetchone()[1] == ip:
    #     print('LogIn Successful') 


def ip_exist(ip):
    conn = sqlite3.connect(drop_db)
    cur = conn.cursor()
    response = conn.execute("SELECT EXISTS(SELECT 1 FROM ip2drop WHERE ip=?)", (ip,))
    fetched = response.fetchone()[0]
    if fetched == 1:
        # print("Exist")
        return True
    else:
        # print("Does not exist")
        return False


## Firewall Operations

def remove_ip_from_firewall(ip):
    os.system("firewall-cmd --zone=drop --remove-source=" + ip)


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
    else:
        print(f'IP: {ip} not exist in DB')


def export_log(command, desctination):
    os.system(command + ' > ' + desctination)


def get_log(log, threshold, excludes, showstat):
    print(f'Processing log: {log}')
    with open(log, "r") as f:
        ips = Counter(extract_ip(line) for line in f)

        exclude_from_check = excludes.split(' ')
        # print(exclude_from_check)

        for ip, count in ips.items():
            # print(ip, '->', count)
            if ip in exclude_from_check:
                print (f'Ignore IP from checking: {ip}')
            elif count >= threshold:
                int_ip = int(ipaddress.IPv4Address(ip))
                # print(int_ip)

                frop_int = ipaddress.IPv4Address(int_ip)
                # print(frop_int)
                if showstat:
                    print('Action without drop: Show threshold count exceeded')
                    print(f'Found: {ip} -> Threshold: {count}')
                    # TODO: need to coding
                else:
                    print(f'Action drop: {ip} -> Threshold: {count}')
                    os.system("firewall-cmd --zone=drop --add-source=" + ip)

                    # Drop time
                    currentDate = datetime.datetime.now()
                    # Drop end
                    undropDate = currentDate + datetime.timedelta(seconds=ip_timeoit)

                    # Check true
                    if ip_exist(ip):
                        print(f'IP exist: {ip}')
                    else:
                        add_drop_ip(ip, int_ip, 1, undropDate, currentDate, 'testing')
            else:
                print(f'Attack with threshold ({ip_threshold}) conditions  not detected.')


def print_db_entries():
    con = sqlite3.connect(drop_db)
    cur = con.cursor()

    for row in cur.execute('SELECT * FROM ip2drop;'):
        print(row)

    con.close()


def arg_parse():
    parser = argparse.ArgumentParser(description=arf_default_msg)
    parser.add_argument('-c', '--command', dest='command', type=str, help='Command for execute', default=export_command)
    parser.add_argument('-l', '--logfile', dest='logfile', type=str, help='Log file name', default=ctl_log_file)
    parser.add_argument('-t', '--threshold', dest='threshold', type=int, help='Ban time', default=ip_threshold)
    parser.add_argument('-d', '--delete', dest='delete', type=str, help='Delete IP from database')
    parser.add_argument('-e', '--excludes', dest='excludes', help="Excludes IP list with space separated", default=ip_excludes)
    parser.add_argument('-s', '--stat', action='store_true', help='Show status without drop',
                        default=False)
    parser.add_argument('-p', '--print', action='store_true', help='Print data drom DB',
                        default=False)

    # args = parser.parse_args()
    return parser.parse_args()


def main():
    args = arg_parse()

    ctl_log = f'{ctl_log_dir}/{args.logfile}'

    check_dir(ctl_log_dir)
    check_file(ctl_log)

    if args.stat:
        print('Stat is enable')

    if args.print:
        print('Print is enable')
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

    export_log(args.command, ctl_log)
    get_log(ctl_log, args.threshold, args.excludes, args.stat)


if __name__ == "__main__":
    main()

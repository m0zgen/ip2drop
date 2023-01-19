#!/usr/bin/env python3

import os
import re
import sqlite3
import datetime
import ipaddress
import subprocess
from collections import Counter
import datetime
import argparse

ip_timeoit = 10
ip_threshold = 150
ctl_log_file = "ip2drop.log"
ctl_log_dir = f'{os.getcwd()}/log'
export_command = "journalctl -u ssh -S today --no-tail | grep 'Connection closed by authenticating user root'"

drop_db = "db.sql"
drop_db_schema = "db_schema.sql"
arf_default_msg = "Drop IP Information"

## 

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


##

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


##

def add_drop_ip(ip, ip_int, status, timeout, date, group):
    conn = sqlite3.connect(drop_db)
    cursor = conn.cursor()
    params = (ip, ip_int, status, timeout, date, group)
    cursor.execute("INSERT INTO ip2drop VALUES (?,?,?,?,?,?)", params)
    conn.commit()
    print('Drop Entry Created Successful')
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
    else:
        print("Does not exist")

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


def get_ip(line):
    ip = line.split(" ")[9]
    return ip


def extract_ip(line):
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ip = pattern.search(line)[0]
    return ip


def export_log(command, desctination):
    os.system(command + ' > ' + desctination)


def get_log(log, threshold):
    with open(log, "r") as f:
        ips = Counter(extract_ip(line) for line in f)

        for ip, count in ips.items():
            # print(ip, '->', count)
            if count > threshold:
                print(f'{ip} -> {count}')

                int_ip = int(ipaddress.IPv4Address(ip))
                # print(int_ip)

                frop_int = ipaddress.IPv4Address(int_ip)
                # print(frop_int)
                os.system("firewall-cmd --zone=drop --add-source=" + ip)

                currentDate = datetime.datetime.now()

                # Check true
                if ip_exist(ip):
                    print(f'IP exist: {ip}')
                else:
                    add_drop_ip(ip, int_ip, 1, 120, currentDate, 'testing')


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

    # args = parser.parse_args()
    return parser.parse_args()


def main():
    args = arg_parse()

    ctl_log = f'{ctl_log_dir}/{args.logfile}'
    print(ctl_log)
    check_dir(ctl_log_dir)
    check_file(ctl_log)

    print(f'Checking threshold: {args.threshold}')

    export_log(args.command, ctl_log)
    get_log(ctl_log, args.threshold)


if __name__ == "__main__":
    main()

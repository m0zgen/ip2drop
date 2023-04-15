#!/usr/bin/env python3
# Author: Yevgeniy Goncharov, https://lab.sys-adm.in
# Helper for ip2drop script. Status: testing
import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.append(str(Path(sys.argv[0]).absolute().parent.parent))
from app import var
from app.var import SERVER_MODE
from app import lib

# Variables
# ------------------------------------------------------------------------------------------------------/

# Init Section
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = var.CONFIG

# Datetime Format for Journalctl exported logs
DATETIME_DEFAULT_FORMAT = '%Y-%m-%d %H:%M:%S.%f'

DROP_DB_CLEAN_DAYS = CONFIG['MAIN']['DROP_DB_CLEAN_DAYS']

# Arguments parser section
# ------------------------------------------------------------------------------------------------------/
parser_helper = argparse.ArgumentParser(description='IP2DROP helper')
parser_helper.add_argument('-p', '--print', help='Show all records from table ip2drop', default=False,
                           action='store_true')
parser_helper.add_argument('-r', '--increment', help='Increment count by 1', default=False, action='store_true')
parser_helper.add_argument('-a', '--all', help='Show all IP from tables', default=False, action='store_true')
parser_helper.add_argument('-t', '--timeout', help='Check timeout IP', default=False, action='store_true')
parser_helper.add_argument('-s', '--show', help='Show info', default=False, action='store_true')
parser_helper.add_argument('-i', '--ip', help='Get IP address info')
parser_helper.add_argument('-c', '--count', help='Reset Count')
args_helper = parser_helper.parse_args()
print_all = args_helper.print
ip = args_helper.ip
if_increment = args_helper.increment
if_show = args_helper.show
if_all = args_helper.all
if_timeout = args_helper.timeout
count = args_helper.count


# Functions
# ------------------------------------------------------------------------------------------------------/
def show_info():
    lib.msg_info(f'Loaded config: {var.LOADED_CONFIG}')
    lib.msg_info(f'Server mode: {SERVER_MODE}')
    lib.msg_info(f'Config DB: {var.DROP_DB}')


# Connect to sqlite3
# ------------------------------------------------------------------------------------------------------/
def connect_db():
    try:
        conn = sqlite3.connect(var.DROP_DB)
        return conn
    except sqlite3.Error as e:
        print(e)
    return None


# Print all tables
# ------------------------------------------------------------------------------------------------------/
def print_all_tables():
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    print(c.fetchall())


# Show all records from table ip2drop
# ------------------------------------------------------------------------------------------------------/
def show_all_records():
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ip2drop")
    print(c.fetchall())


# Select columns from table ip2drop by ip
# ------------------------------------------------------------------------------------------------------/
def select_by_ip(ip):
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ip2drop WHERE ip = ?", (ip,))
    print(c.fetchall())


# Update record in table ip2drop by count where count not equal 0
# ------------------------------------------------------------------------------------------------------/
def update_by_count(ip_count):
    conn = connect_db()
    c = conn.cursor()
    c.execute("""UPDATE ip2drop SET COUNT = :COUNT""", {'COUNT': ip_count})
    conn.commit()


drop_date = lib.get_drop_date_from_ip(ip)
timeout = lib.get_timeout_from_ip(ip)

if lib.ip_exist(ip):
    if lib.check_date(ip, drop_date, timeout):
        lib.msg_info(f'IP {ip} need ban again')
        if if_increment:
            lib.msg_info(f'Increment count by 1 for IP {ip} in table ip2drop')
            lib.increment_by_ip(ip)

else:
    lib.msg_info(f'IP {ip} not exist in table ip2drop')


# Iterate all ips from table ip2drop
# ------------------------------------------------------------------------------------------------------/
def export_data_to_json(ip, ip_int, status, count, timeout, drop_date, creatioon_date, group_id):
    data = {
        "ip": ip,
        "ip_int": ip_int,
        "status": status,
        "count": count,
        "timeout": timeout,
        "drop_date": drop_date,
        "creatioon_date": creatioon_date,
        "group_id": group_id
    }
    with open('data.json', 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=False)


def export_data_to_json2(data):
    with open('data2.json', 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=False)


# Select and show all DB records in terminal
def iterate_all_ips():
    data = []
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ip2drop")
    # print(c.fetchall())

    # export_data_to_json2(to_json)

    # Iterate over list c.fetchall()
    # ---------------------------------/
    for row in c.fetchall():
        ip = row[0]
        ip_int = row[1]
        status = row[2]
        count = row[3]
        timeout = row[4]
        drop_date = row[5]
        creatioon_date = row[6]
        group_id = row[7]

        print(f'IP: {ip} (int variant: {ip_int}), '
              f'Drop date: {drop_date}, Status: {status}, '
              f'Count: {count}, Timeout: {timeout}, '
              f'Drop date: {drop_date}, Creation date: {creatioon_date}, '
              f'Group ID: {group_id}')

        # Append data to json file
        # ------------------------------------------------------------------------------------------------------/
        data.append({
            "ip": ip,
            "ip_int": ip_int,
            "status": status,
            "count": count,
            "timeout": timeout,
            "drop_date": drop_date,
            "creatioon_date": creatioon_date,
            "group_id": group_id
        })

        # Export data to json file
        # ------------------------------------------------------------------------------------------------------/
        export_data_to_json(ip, ip_int, status, count, timeout, drop_date, creatioon_date, group_id)

        if lib.check_date(ip, drop_date, timeout):
            lib.msg_info(f'IP {ip} need ban again')
            if if_increment:
                lib.msg_info(f'Increment count by 1 for IP {ip} in table ip2drop')
                lib.increment_by_ip(ip)

        export_data_to_json2(data)


print_all_tables()

if if_show:
    show_info()

if print_all:
    show_all_records()
    exit(0)

if count:
    print("Count: " + count)
    update_by_count(count)
    exit(0)

if ip:
    select_by_ip(ip)

# If show all ips
if if_all:
    iterate_all_ips()


# Check passed argument -t
if if_timeout:
    # Check if ip exist in DB
    if lib.ip_exist(ip):
        # Get timeout date from DB for ip
        timeout = lib.get_timeout_from_ip(ip)
        print(f'IP: {ip}, Timeout: {timeout}')

        # Check timeout date less than current date more than 1 month (DROP_DB_CLEAN)
        if lib.check_timeout_date(ip, timeout):
            lib.msg_info(f'IP {ip} need delete from DB')
            # Delete record from DB
            lib.delete_record_from_db(ip)
            lib.msg_info(f'IP {ip} deleted from DB')
    else:
        lib.msg_error(f'IP {ip} not found in DB')

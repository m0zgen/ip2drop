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


# Check if ip exist in table ip2drop
# ------------------------------------------------------------------------------------------------------/
def ip_exist(ip):
    conn = connect_db()
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


# Update record in table ip2drop by count where count not equal 0
# ------------------------------------------------------------------------------------------------------/
def update_by_count(ip_count):
    conn = connect_db()
    c = conn.cursor()
    c.execute("""UPDATE ip2drop SET COUNT = :COUNT""", {'COUNT': ip_count})
    conn.commit()


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
    drop_date_as_dt = datetime.strptime(drop_date, DATETIME_DEFAULT_FORMAT)
    timeout_as_dt = datetime.strptime(timeout, DATETIME_DEFAULT_FORMAT)

    print(f'Drop date: {drop_date}, Timeout: {timeout}, Current date: {current_date}')

    # Time delta
    # ------------------------------------------------------------------------------------------------------/

    # String to datetime
    timeout = datetime.strptime(timeout, DATETIME_DEFAULT_FORMAT)
    delta = timeout - current_date

    # print(delta.days)
    # print(delta.seconds)
    # print(delta.microseconds)
    # print(delta.total_seconds())

    if current_date > timeout_as_dt:
        lib.msg_info(f'IP {ip} need ban again. Overdue: {str(delta)}')
        bool_status = True
    else:
        # print("Timeout less than current date. No need action. Left: " + str(delta))
        lib.msg_info(f'{ip} - Timeout is greater than than current date. No need action. Left: {str(delta)}')

    return bool_status


drop_date = get_drop_date_from_ip(ip)
timeout = get_timeout_from_ip(ip)

# print(f'Drop date: {drop_date}, Timeout: {timeout}')

if ip_exist(ip):
    if check_date(ip, drop_date, timeout):
        lib.msg_info(f'IP {ip} need ban again')
        if if_increment:
            lib.msg_info(f'Increment count by 1 for IP {ip} in table ip2drop')
            increment_by_ip(ip)

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

        if check_date(ip, drop_date, timeout):
            lib.msg_info(f'IP {ip} need ban again')
            if if_increment:
                lib.msg_info(f'Increment count by 1 for IP {ip} in table ip2drop')
                increment_by_ip(ip)

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


# TODO: Clean record from DB if timeout less than current date more than 1 month (DROP_DB_CLEAN)

# Delete record from DB if timeout less than current date more than 1 month (DROP_DB_CLEAN)
# ------------------------------------------------------------------------------------------------------/
def delete_record_from_db(ip):
    conn = connect_db()
    c = conn.cursor()
    lib.msg_info(f'Deleting record from DB for IP {ip}')
    c.execute("""DELETE FROM ip2drop WHERE ip = ?""", (ip,))
    conn.commit()


# Check timeout date less than current date more than 1 month (DROP_DB_CLEAN)
# ------------------------------------------------------------------------------------------------------/
def check_timeout_date(ip, timeout):
    current_date = datetime.now()
    bool_status = False

    # Convert list to string
    # ---------------------------------/
    timeout = str(timeout)
    # Convert string to datetime
    # ---------------------------------/
    timeout_as_dt = datetime.strptime(timeout, DATETIME_DEFAULT_FORMAT)

    # timeout_as_dt plus DElETE_DB_CLEAN days
    # ---------------------------------/

    # Convert DROP_DB_CLEAN_DAYS to int
    days = int(DROP_DB_CLEAN_DAYS)
    timeout_as_dt = timeout_as_dt + timedelta(days=days)

    print(f'Timeout + DROP_DB_CLEAN_DAYS {DROP_DB_CLEAN_DAYS} as dt: {timeout_as_dt}. Current date: {current_date}')

    # Time delta
    # ------------------------------------------------------------------------------------------------------/

    # String to datetime
    timeout_as_dt_str = str(timeout_as_dt)
    timeout_as_dt_str = datetime.strptime(timeout_as_dt_str, DATETIME_DEFAULT_FORMAT)
    delta = timeout_as_dt_str - current_date

    # print(delta.days)
    # print(delta.seconds)
    # print(delta.microseconds)
    # print(delta.total_seconds())

    if current_date > timeout_as_dt:
        lib.msg_info(f'IP {ip} need delete from DB. Overdue: {str(delta)}')
        bool_status = True
    else:
        # print("Timeout less than current date. No need action. Left: " + str(delta))
        lib.msg_info(f'{ip} - Timeout is greater than than current date. No need action. Left: {str(delta)}')

    return bool_status


# Detect time date format from string
# ------------------------------------------------------------------------------------------------------/
def detect_datetime_format(date_string):
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d', DATETIME_DEFAULT_FORMAT):
        try:
            datetime.strptime(date_string, fmt)
            return fmt
        except ValueError:
            pass
    raise ValueError('no valid date format found')


# Get timeout date from DB for ip
# ------------------------------------------------------------------------------------------------------/
def get_timeout_from_ip(ip):
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT timeout FROM ip2drop WHERE ip = ?", (ip,))
    timeout = c.fetchone()[0]

    # Convert list to string
    # ---------------------------------/
    # timeout = str(timeout)
    # print(f'Timeout: {timeout}')

    # Check format
    # ---------------------------------/
    # detect_datetime_format(timeout)

    # Convert string to datetime
    # ---------------------------------/
    # timeout_as_dt = datetime.strptime(timeout, DATETIME_DEFAULT_FORMAT)

    return timeout


if if_timeout:

    if ip_exist(ip):

        timeout = get_timeout_from_ip(ip)
        print(f'IP: {ip}, Timeout: {timeout}')

        if check_timeout_date(ip, timeout):
            lib.msg_info(f'IP {ip} need delete from DB')
            delete_record_from_db(ip)
            lib.msg_info(f'IP {ip} deleted from DB')
    else:
        lib.msg_error(f'IP {ip} not found in DB')



#!/usr/bin/env python3
# Author: Yevgeniy Goncharov, https://lab.sys-adm.in
# Helper for ip2drop script. Status: testing
import argparse
import os
import sqlite3
import sys
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

lib.msg_info(f'Loaded config: {var.LOADED_CONFIG}')
lib.msg_info(f'Server mode: {SERVER_MODE}')
lib.msg_info(f'Config DB: {var.DROP_DB}')

# Arguments parser section
# ------------------------------------------------------------------------------------------------------/
parser = argparse.ArgumentParser(description='IP2DROP helper')
parser.add_argument('-p', '--print', help='Show all records from table ip2drop', default=False, action='store_true')
parser.add_argument('-i', '--ip', help='Get IP address info')
parser.add_argument('-c', '--count', help='Reset Count')
args = parser.parse_args()
print_all = args.print
ip = args.ip
count = args.count


# Functions
# ------------------------------------------------------------------------------------------------------/


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


print_all_tables()


# Show all records from table ip2drop
# ------------------------------------------------------------------------------------------------------/
def show_all_records():
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ip2drop")
    print(c.fetchall())


if print_all:
    show_all_records()


# Select columns from table ip2drop by ip
# ------------------------------------------------------------------------------------------------------/
def select_by_ip(ip):
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ip2drop WHERE ip = ?", (ip,))
    print(c.fetchall())


if ip:
    select_by_ip(ip)


# Update record in table ip2drop by count where count not equal 0
# ------------------------------------------------------------------------------------------------------/
def update_by_count(ip_count):
    conn = connect_db()
    c = conn.cursor()
    c.execute("""UPDATE ip2drop SET COUNT = :COUNT""", {'COUNT': ip_count})
    conn.commit()


if count:
    print("Count: " + count)
    update_by_count(count)

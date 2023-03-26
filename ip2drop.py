#!/usr/bin/env python3
# Author: Yevgeniy Goncharov, https://lab.sys-adm.in
# Find malicious IP addresses through executed command and send it's to firewalld drop zone for relaxing)
import bisect
import difflib
import filecmp
import requests
# Imports
# ------------------------------------------------------------------------------------------------------/
import os
import re
import shutil
import sys
import argparse
import ipaddress
import datetime
import subprocess
import sqlite3
from collections import Counter
from pathlib import Path
import json

# TODO: mem / cpu thresholding
# modules=['psutil','numpy']

# Import app
sys.path.append(str(Path(sys.argv[0]).absolute().parent.parent))
from app import var
from app.var import SERVER_MODE
from app import lib

# Variables
# ------------------------------------------------------------------------------------------------------/

# Init Section
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = var.CONFIG

# Load Options
IP_TIMEOUT = CONFIG['DEFAULT'].getint('IP_TIMEOUT')
IP_THRESHOLD = CONFIG['DEFAULT'].getint('IP_THRESHOLD')
EXPORT_COMMAND = CONFIG['DEFAULT']['EXPORT_COMMAND']
EXPORT_LOG = CONFIG['DEFAULT']['EXPORT_LOG']
GROUP_NAME = CONFIG['DEFAULT']['GROUP_NAME']
IP_EXCLUDES = CONFIG['MAIN']['IP_EXCLUDES']
IPSET_NAME = CONFIG['MAIN']['IPSET_NAME']
IPSET_ENABLED = CONFIG['MAIN'].getboolean('IPSET_ENABLED')
EXPORT_TO_UPLOAD = CONFIG['DEFAULT'].getboolean('EXPORT_TO_UPLOAD')
DROP_DIRECTLY = CONFIG['DEFAULT'].getboolean('DROP_DIRECTLY')
SKIP_DEFAULT_RULE = CONFIG['MAIN'].getboolean('SKIP_DEFAULT_RULE')
# print(f'TIMEOUT: {IP_TIMEOUT}, COMMAND: {EXPORT_COMMAND}, ENABLED: {IPSET_ENABLED}')

# Datetime Format for Journalctl exported logs
DATETIME_DEFAULT_FORMAT = '%Y-%m-%d %H:%M:%S.%f'
TODAY = datetime.date.today()
IP_NONE = "None"

# Database Schema
DROP_DB_NAME = var.DROP_DB_NAME
DROP_DB = var.DROP_DB
DROP_DB_SCHEMA = var.DROP_DB_SCHEMA
ARG_DEFAULT_MSG = var.ARG_DEFAULT_MSG

# Conf.d loader
if SERVER_MODE == 'Production':
    D_CONFIG_FILES, D_CONFIG_COUNT = var.get_prod_config_files()
else:
    D_CONFIG_FILES, D_CONFIG_COUNT = var.get_config_files()

# get_prod_config_files

# print(D_CONFIG_FILES)

# Dynamics
HOSTNAME = CONFIG['MAIN']['HOSTNAME']
USERNAME = CONFIG['MAIN']['USERNAME']

# Uploading to local folder
IS_UPLOAD_ENABLED = CONFIG['MAIN'].getboolean('UPLOAD')
UPLOAD_PREFIX = f'{HOSTNAME}'.format(HOSTNAME=lib.get_hostname())
UPLOAD_DIR_RELATIVE = CONFIG['MAIN']['UPLOAD_DIR']
UPLOAD_DIR = os.path.join(BASE_DIR, UPLOAD_DIR_RELATIVE)
UPLOAD_BASE_FILE_NAME = CONFIG['MAIN']['UPLOAD_FILE']
UPLOAD_FILE_NAME = f'{UPLOAD_PREFIX}_{UPLOAD_BASE_FILE_NAME}'
UPLOAD_FILE = os.path.join(UPLOAD_DIR, UPLOAD_FILE_NAME)

# Upload remote
UPLOAD_TO_SERVER = CONFIG['MAIN'].getboolean('UPLOAD_TO_SERVER')
UPLOAD_SERVER = CONFIG['MAIN']['UPLOAD_SERVER']
UPLOAD_PROTOCOL = CONFIG['MAIN']['UPLOAD_PROTOCOL']


# Arguments parser
# ------------------------------------------------------------------------------------------------------/
def arg_parse():
    parser = argparse.ArgumentParser(description=ARG_DEFAULT_MSG)
    parser.add_argument('-c', '--command', dest='command', type=str, help='Command for execute', default=EXPORT_COMMAND)
    parser.add_argument('-l', '--logfile', dest='logfile', type=str, help='Log file name', default=EXPORT_LOG)
    parser.add_argument('-t', '--threshold', dest='threshold', type=int, help='Dropping time', default=IP_THRESHOLD)
    parser.add_argument('-o', '--timeout', dest='timeout', type=int, help='Un-drop time', default=IP_TIMEOUT)
    parser.add_argument('-g', '--group', dest='group', type=str, help='Grouping rule name', default=GROUP_NAME)
    parser.add_argument('-d', '--delete', dest='delete', type=str, help='Delete IP from database')
    parser.add_argument('-e', '--excludes', dest='excludes', help="Excludes IP list with space separated",
                        default=IP_EXCLUDES)
    parser.add_argument('-r', '--rebind', action='store_true', help='Rebind (reset) ipset and DB',
                        default=False)
    parser.add_argument('-s', '--stat', action='store_true', help='Show status without drop',
                        default=False)
    parser.add_argument('-p', '--print', action='store_true', help='Print data from DB',
                        default=False)
    parser.add_argument('-pr', '--printroutines', action='store_true', help='Print routines from DB',
                        default=False)
    parser.add_argument('-pc', '--printconfig', action='store_true', help='Print configs data',
                        default=False)
    parser.add_argument('-id', '--includedefault', action='store_true', help='Include default rule',
                        default=False)
    # args = parser.parse_args()
    return parser.parse_args()


#
# ------------------------------------------------------------------------------------------------------/
def check_start_end(current_timeout, time_difference, log):
    # Timing processes
    log_time_format = '%H:%M:%S'

    # start_cheking_time = datetime.datetime.strptime(current_timeout, '%H:%M:%S').time()
    end_checking_time = lib.get_current_time().strftime('%H:%M:%S')

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


def get_app_json(file):
    data = ""
    try:
        with open(file) as json_file:
            data = json.load(json_file)
            # print(data['ip2drop']['author'])
            return data
    except:
        return data


def rebind_db(previous_db):
    lib.check_dir(var.BACKUP_DIR)
    postfix_name = datetime.datetime.now().strftime("%Y-%m-%d_%I-%M-%S_%p")
    new_name = DROP_DB_NAME + '_v_' + str(previous_db) + '_' + postfix_name
    print(new_name)
    os.rename(DROP_DB, os.path.join(var.BACKUP_DIR, new_name))
    # subprocess.call("cp %s %s" % (DROP_DB, var.BACKUP_DIR), shell=True)
    var.create_db_schema()


def check_app_versioning():
    app_json_data = get_app_json(var.APP_JSON)

    if app_json_data != "":
        # print(app_json_data)
        previous_db = app_json_data['ip2drop']['previous_database_version']
        current_db = app_json_data['ip2drop']['current_database_version']
        if previous_db < current_db:
            lib.msg_info(f'Need update DB. Current version: {previous_db}. Next release: {current_db}')
            rebind_db(previous_db, current_db)
            app_json_data['ip2drop']['previous_database_version'] = current_db
            with open(var.APP_JSON, "w") as jsonFile:
                json.dump(app_json_data, jsonFile, indent=4, sort_keys=True)
    else:
        print(f'App JSON not found')


def print_config():
    last_scan = get_last_scan_time()
    lib.msg_info(
        f'Loaded config: {var.LOADED_CONFIG}\n'
        f'System log: {lib.SYSTEM_LOG}\n'
        f'Server mode: {var.SERVER_MODE}\n'
        f'Last scan: {last_scan}')

    app_json_data = get_app_json(var.APP_JSON)
    author = app_json_data['ip2drop']['author']
    site = app_json_data['ip2drop']['site']
    db_version = app_json_data['ip2drop']['current_database_version']
    script_version = app_json_data['ip2drop']['current_script_version']
    lib.msg_info(
        f'DB Version: {db_version}\n'
        f'ip2drop Version: {script_version}\n'
        f'Author: {author}\n'
        f'Site: {site}')
    username = f'{USERNAME}'.format(USERNAME=lib.get_username())
    print("Hostname is {HOSTNAME}".format(HOSTNAME=lib.get_hostname()))
    print(f'Username: {username}')
    lib.msg_info(
        f'Sever: {UPLOAD_SERVER}, Protocol: {UPLOAD_PROTOCOL}, Upload enabled? {UPLOAD_TO_SERVER}')
    exit(0)


def print_foundcount(found_count, showstat, log_len):
    if found_count == 0:
        if not showstat:
            lib.msg_info(f'Info: Thread does not found.')
            # TODO: need show counts for ip lists in stat
        else:
            if log_len != 0:
                lib.msg_info(f'Log count: {log_len}')
            else:
                lib.msg_info(f'Info: Thread does not found.')
    else:
        lib.msg_info(f'Info: Found count: {found_count}')


# DB Operations
# ------------------------------------------------------------------------------------------------------/

def add_drop_ip(ip, ip_int, status, count, timeout, drop_date, date_added, group):
    conn = sqlite3.connect(DROP_DB)
    cursor = conn.cursor()
    params = (ip, ip_int, status, count, timeout, drop_date, date_added, group)
    cursor.execute("INSERT INTO ip2drop VALUES (?,?,?,?,?,?,?,?)", params)
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
    cur.execute("""UPDATE ip2drop SET COUNT = :COUNT WHERE IP =:IP """, {'COUNT': count, 'IP': ip})
    conn.commit()
    print("Update Count Status Successful")
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
    print("Update Drop Status Successful")
    conn.close()


def update_unban_date(unban_date, ip):
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    # cur.execute('''UPDATE ip2drop SET status = ? WHERE ip = ?''', (status, ip))
    cur.execute("""UPDATE ip2drop SET TIMEOUT = :TIMEOUT WHERE IP =:IP """, {'TIMEOUT': unban_date, 'IP': ip})
    conn.commit()
    print("Update Undrop Status Successful")
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
    lib.msg_info(f'Mode: Print DB records.')
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    for row in cur.execute('SELECT * FROM ip2drop;'):
        print(row)
    conn.close()


def print_routine_entries():
    lib.msg_info(f'Mode: Print Routine records.')
    conn = sqlite3.connect(DROP_DB)
    cur = conn.cursor()
    for row in cur.execute('SELECT * FROM routines;'):
        print(row)
    conn.close()


def add_routine_scan_time(last_scan):
    conn = sqlite3.connect(DROP_DB)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO routines VALUES (NULL, ?)", (last_scan,))
    conn.commit()
    print("Add Runtime Successful")
    conn.close()


def get_last_scan_time():
    conn = sqlite3.connect(DROP_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routines ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    return result


# def get_last_log_time(log):


# Firewall Operations
# ------------------------------------------------------------------------------------------------------/
def add_ip_to_firewalld(ip):
    os.system("firewall-cmd --zone=drop --add-source=" + ip)
    lib.log_warn(f'{ip} added to firewalld.')


def remove_ip_from_firewall(ip):
    os.system("firewall-cmd --zone=drop --remove-source=" + ip)
    lib.log_warn(f'{ip} removed from firewalld.')


def add_ip_to_ipset(ip, timeout):
    timeout = str(timeout)
    # -!
    cmd = "ipset -! add " + IPSET_NAME + " " + ip + " timeout " + timeout
    os.system(cmd)
    lib.log_info(f'Added to ipset: {ip}')


def remove_ip_from_ipset(ip):
    cmd = "ipset del " + IPSET_NAME + " " + ip
    os.system(cmd)


def delete_ip(ip):
    if ip_exist(ip):
        print(f'IP: {ip} will be deleted')
        delete_dropped_ip(ip)

        if IPSET_ENABLED:
            remove_ip_from_ipset(ip)
        else:
            remove_ip_from_firewall(ip)

        lib.log_info(f'IP: {ip} deleted from DB: {DROP_DB}')
    else:
        print(f'IP: {ip} not exist in DB')
        lib.log_info(f'IP: {ip} not exist in DB')


# Log parsing
# ------------------------------------------------------------------------------------------------------/
def get_ip(line):
    ip = line.split(" ")[9]
    return ip


# Extract IPv4 only
def extract_ip(line):
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    try:
        ip = pattern.search(line)[0]
    except:
        # msg_info(f'LINE: {line}')
        # IPv6 or not determine data in line
        ip = IP_NONE
    return ip


# Log Processing
# ------------------------------------------------------------------------------------------------------/
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

def _showstat(ip, count):
    print(f'Warning: Found - {ip} -> Threshold: {count} (Show stat found without drop)')
    lib.log_warn(f'Action without drop. Found: {ip} -> Threshold: {count}')


def _review_exists(ip):
    creation_date = lib.get_current_time()
    current_timeout = get_timeout(ip)

    try:
        last_scan_date = get_last_scan_time()[1]
    except:
        add_routine_scan_time(lib.get_current_time())

    # last_log_time =

    # Format: 2023-02-11 18:27:50.192957
    time_difference = creation_date - datetime.datetime.strptime(current_timeout,
                                                                 DATETIME_DEFAULT_FORMAT)
    total_seconds = time_difference.total_seconds()
    # print(f'Timeout: {time_difference}')
    # print(f'Total seconds: {total_seconds}')
    # check_start_end(current_count, time_difference, log)

    # TODO: Get out time

    # current_delta = current_timeout - datetime.datetime.strptime(str(current_time),
    #                                                              DATETIME_DEFAULT_FORMAT)

    current_delta = datetime.datetime.strptime(current_timeout, DATETIME_DEFAULT_FORMAT) - creation_date

    # TODO: Add and update drop counts
    # lib.msg_info(f'Info: IP exist in Drop DB: {ip}. '
    # f'Current time: {creation_date} till to: {current_timeout}. Delta: {current_delta}')

    if "-" in str(current_delta):
        lib.msg_info(f'Timeout expired: {current_delta}')
        return True
    else:
        return False


def _drop_simple(ip, timeout):
    # lib.msg_info(f'Adding: {ip}')
    # Ban
    if IPSET_ENABLED:
        # TODO: Need update till to in DB!
        # lib.msg_info(f'Timeout: {timeout}')
        add_ip_to_ipset(ip, timeout)
    else:
        add_ip_to_firewalld(ip)


def _drop(ip, timeout, count, again):
    print(f'\nAction: Drop: {ip} -> Threshold: {count}')
    # Ban
    if IPSET_ENABLED:
        # TODO: Need update till to in DB!
        lib.msg_info(f'Timeout: {timeout}')
        add_ip_to_ipset(ip, timeout)
    else:
        add_ip_to_firewalld(ip)

    # Update in DB
    if again:
        current_count = get_drop_count(ip)
        current_count = lib.increment(current_count)
        update_drop_count(current_count, ip)

    current_date = lib.get_current_time()
    undrop_date = current_date + datetime.timedelta(seconds=timeout)
    update_unban_date(undrop_date, ip)
    update_drop_status(1, ip)


def whitespace_only(file):
    content = open(file, 'r').read()
    if re.search(r'^\s*$', content):
        return True


def drop_now(log, threshold, timeout, group_name, showstat, excludes):
    if threshold < 0 and not showstat:

        log_prev = log + "_prev"
        log_ip = []
        found_count = 0
        log_compared = var.EXPORTED_LOGS_DIR + "/" + group_name + "_cmp.log"
        log_len = len(open(log).readlines())
        exclude_from_check = excludes.split(' ')

        if os.path.exists(log_prev):

            cmp = filecmp.cmp(log, log_prev, shallow=False)

            if not cmp:
                lib.msg_info(f'Log files not seem equal...')
                with open(log_prev) as log_1, open(log) as log_2:
                    log_1_text = log_1.readlines()
                    log_2_text = log_2.readlines()

                # File method
                with open(log_compared, 'w') as outFile:
                    lib.msg_info(f'Comparsing...')
                    for line in log_2_text:
                        print('\r', extract_ip(line), end=' ')
                        if line not in log_1_text:
                            outFile.write(line)

                if not whitespace_only(log_compared):
                    with open(log_compared, "r") as f:
                        for line in f:
                            ip = extract_ip(line)
                            _drop_simple(ip, timeout)
                            found_count = lib.increment(found_count)

            else:
                lib.msg_info(f'Log files seem equal. Ok.')


        else:
            with open(log, "r") as f:
                for line in f:
                    log_ip.append(line)

            for line in log_ip:
                ip = extract_ip(line)
                _drop_simple(ip, timeout)
                print('\r', str(ip), end=' ')
                found_count = lib.increment(found_count)
                # lib.msg_info(f'IP: {ip}')

        shutil.copyfile(log, log_prev)

        if found_count != 0:
            lib.msg_info(f'Found count in drop directly: {found_count}')
        print_foundcount(found_count,showstat, log_len)


def generate_upload_file(ip, export_to_upload):
    if IS_UPLOAD_ENABLED:
        if export_to_upload:
            lib.append_to_file(UPLOAD_FILE, ip)


def post_upload_file():
    if UPLOAD_TO_SERVER:
        if lib.check_http_200(UPLOAD_SERVER):
            lib.msg_info(f'Upload server available: {UPLOAD_SERVER}')
            if os.path.exists(UPLOAD_FILE):
                access_token = HOSTNAME + "-token"
                hdr = {"Authorization": "Bearer %s" % access_token}
                with open(UPLOAD_FILE, "rb") as fobj:
                    file_obj = fobj.read()
                    file_basename = os.path.basename(UPLOAD_FILE)
                    file_to_upload = {"file": (str(file_basename), file_obj)}
                    finfo = {"fullPath": UPLOAD_FILE}
                    upload_response = requests.post(UPLOAD_SERVER, headers=hdr, files=file_to_upload, data=finfo)
                    fobj.close()
                # print("Status Code ", upload_response.status_code)
                # print("JSON Response ", upload_response.json())
                return upload_response


# General
def get_log(log, threshold, timeout, group_name, export_to_upload, excludes, showstat, drop_directly):
    lib.msg_info(f'Info: Processing log: {log}')
    # TODO: add to routines table:
    found_count = 0

    if drop_directly:
        # found_count = 
        drop_now(log, threshold, timeout, group_name, showstat, excludes)

    with open(log, "r") as f:
        # Count IPv4 if IPv6 - return None
        ips = Counter(extract_ip(line) for line in f)
        exclude_from_check = excludes.split(' ')
        log_len = len(open(log).readlines())
        log_size = os.path.getsize(log)
        

        for ip, count in ips.items():
            # print(ip, '->', count)

            # Checking excludes list
            if ip in exclude_from_check:
                lib.msg_info(f'Info: Found Ignored IP: {ip} with count: {count}')
                found_count = lib.increment(found_count)

            # elif threshold < 0 and ip != IP_NONE and not showstat:
            #     if not drop_directly:
            #         drop_now(log, threshold, timeout, showstat)

            # Checking threshold
            elif count >= threshold and threshold > 0 and ip != IP_NONE:
                int_ip = int(ipaddress.IPv4Address(ip))
                # IP from int converter
                from_int = ipaddress.IPv4Address(int_ip)
                # print(from_int)
                found_count = lib.increment(found_count)

                generate_upload_file(ip, export_to_upload)

                # Show threshold statistic without drop (arg: -s)
                if showstat:
                    _showstat(ip, count)

                else:
                    # TODO: Need to remove this section
                    # TODO: All IP need to append to ipset through text list

                    # Add DB Record time
                    # TODO: Need to Fix Drop time
                    creation_date = lib.get_current_time()

                    # IN DEVELOP:
                    # Exists in Drop
                    if ip_exist(ip):
                        _drop(ip, timeout, count, True)
                        # if _review_exists(ip):
                        #     lib.msg_info(f'Need ban again {ip}')
                        #     _drop(ip, timeout, count, True)

                    else:
                        # Drop / Re-Drop
                        drop_date = creation_date
                        # Un Drop end
                        undrop_date = creation_date + datetime.timedelta(seconds=timeout)

                        # Add to DB
                        add_drop_ip(ip, int_ip, 1, 1, undrop_date, drop_date, creation_date, group_name)
                        lib.log_info(f'Add drop IP to DB: {ip}')

                        # Ban
                        _drop(ip, timeout, count, False)
                        # print(f'Action: Drop: {ip} -> Threshold: {count}')
                        # os.system("firewall-cmd --zone=drop --add-source=" + ip)
                    # found_count = increment(found_count)
                    # TODO: else decrease count
            # else:
            #     print(f'Attack with threshold ({IP_THRESHOLD}) conditions  not detected.')
    if not drop_directly:
        print_foundcount(found_count, showstat, log_len)

    # print(f'Found count: {found_count}')


# Main
# ------------------------------------------------------------------------------------------------------/
def main():
    args = arg_parse()
    check_app_versioning()

    if IS_UPLOAD_ENABLED:
        lib.check_dir(UPLOAD_DIR)
        lib.check_file(UPLOAD_FILE)
        lib.truncate_file(UPLOAD_FILE)

    # Dirty step
    # TODO: Need to make more beauty)
    # print(type(IPSET_NAME))
    if args.rebind:
        set_script = os.path.join(var.HELPERS_DIR, "rebind.sh")
        res = subprocess.call([set_script, IPSET_NAME])
        if res:
            lib.msg_info("Info: Required components not installed in system. Please see messages above. Exit. Bye.")
            exit(1)

        rebind_db("rebind")
        exit(0)

    if IPSET_ENABLED:
        set_script = os.path.join(var.HELPERS_DIR, "set-ipset.sh")
        # subprocess.run([set_script, IPSET_NAME])
        # cmd = shlex.split(cmd_line)
        # bash_command(cmd)
        res = subprocess.call([set_script, IPSET_NAME])
        if res:
            lib.msg_info("Info: Required components not installed in system. Please see messages above. Exit. Bye.")
            exit(1)

    # Create db if not exists
    if not os.path.exists(var.DB_DIR):
        lib.check_dir(var.DB_DIR)
        var.create_db_schema()

    # Log file for command processing
    # today_log = append_id(args.logfile)
    # ctl_log = os.path.join(var.EXPORTED_LOGS_DIR, today_log)
    ctl_log = os.path.join(var.EXPORTED_LOGS_DIR, args.logfile)

    # Checking & creating needed dirs and files
    lib.check_dir(var.EXPORTED_LOGS_DIR)
    lib.check_file(ctl_log)

    if args.stat:
        lib.msg_info('Mode: Show statistics without actions')

    if args.print:
        var.check_db(DROP_DB)
        print_db_entries()
        exit(0)

    if args.printroutines:
        var.check_db(DROP_DB)
        print_routine_entries()
        exit(0)

    if args.printconfig:
        print_config()

    if args.delete is not None:
        delete_ip(args.delete)
        exit(0)

    # if args.delete:
    #     print('Delete IP from DB')
    #     exit(0)

    # print(f'Using command: {args.command}')
    # print(f'Checking threshold: {args.threshold}')
    lib.log_info(f'ip2drop started with params:')
    lib.log_info(f'Command: {args.command} Log: {ctl_log} Threshold {args.threshold} Stat: {args.stat}')

    # Main functions
    if not SKIP_DEFAULT_RULE or args.includedefault:
        export_log(args.command, ctl_log)
        get_log(ctl_log, args.threshold, args.timeout, args.group, EXPORT_TO_UPLOAD, args.excludes, args.stat,
                DROP_DIRECTLY)

    # Each configs
    if D_CONFIG_COUNT > 0:
        for D_CONFIG in D_CONFIG_FILES:
            CONFIG.read(D_CONFIG)
            d_enabled = CONFIG['DEFAULT'].getboolean('ENABLED')
            if d_enabled:
                d_export_cmd = CONFIG['DEFAULT']['EXPORT_COMMAND']
                d_ip_treshold = CONFIG['DEFAULT'].getint('IP_THRESHOLD')
                d_ip_timeout = CONFIG['DEFAULT'].getint('IP_TIMEOUT')
                d_export_log = os.path.join(var.EXPORTED_LOGS_DIR, CONFIG['DEFAULT']['EXPORT_LOG'])
                d_group_name = CONFIG['DEFAULT']['GROUP_NAME']
                d_export_to_upload = CONFIG['DEFAULT'].getboolean('EXPORT_TO_UPLOAD')
                d_drop_directly = CONFIG['DEFAULT'].getboolean('DROP_DIRECTLY')
                lib.check_file(d_export_log)
                export_log(d_export_cmd, d_export_log)
                get_log(d_export_log, d_ip_treshold, d_ip_timeout, d_group_name, d_export_to_upload, args.excludes,
                        args.stat, d_drop_directly)

    add_routine_scan_time(lib.get_current_time())
    lib.msg_info(f'Upload file response:')
    print(post_upload_file())


# Init starter
if __name__ == "__main__":
    raise SystemExit(main())

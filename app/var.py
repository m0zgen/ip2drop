import os
import configparser

# Functions
def get_base_dir():
    base = os.path.join(os.getcwd())  # .. means parent directory

    # Return the absolute path of the parent directory
    return os.path.abspath(base)


def up(n, nth_dir=os.getcwd()):
    while n != 0:
        nth_dir = os.path.dirname(nth_dir)
        n -= 1
    print(nth_dir)
    return nth_dir


def get_current_dir():
    return os.path.dirname(os.path.abspath(__file__))


def get_up_dir():
    return os.path.dirname(get_current_dir())


def get_script_dir():
    current = get_current_dir()
    up_dir = os.path.dirname(current)
    return up_dir


def get_parent_directory():
    # Create a relative path to the parent of the current working directory
    relative_parent = os.path.join(os.getcwd(), "..")  # .. means parent directory
    # Return the absolute path of the parent directory
    return os.path.abspath(relative_parent)


# Vars
APP_ENV = os.getenv("IP2DROP_ENV")

PARENT_DIR = get_parent_directory()
CURR_DIR = get_current_dir()
BASE_DIR = get_up_dir()

# Relative paths
RELATIVE_SRC_DIR = "src/"
RELATIVE_DB_DIR = "db/"
RELATIVE_LOGS_DIR = "logs/"
RELATIVE_CONF_DIR = "conf.d/"
RELATIVE_HELPERS_DIR = "helpers/"
RELATIVE_BACKUP_DIR = "backup/"

DB_DIR = os.path.join(BASE_DIR, RELATIVE_DB_DIR)
SRC_DIR = os.path.join(BASE_DIR, RELATIVE_SRC_DIR)
CONF_DIR = os.path.join(BASE_DIR, RELATIVE_CONF_DIR)
HELPERS_DIR = os.path.join(BASE_DIR, RELATIVE_HELPERS_DIR)
EXPORTED_LOGS_DIR = os.path.join(BASE_DIR, RELATIVE_LOGS_DIR)
BACKUP_DIR = os.path.join(BASE_DIR, RELATIVE_BACKUP_DIR)

# Configs
CONFIG = configparser.ConfigParser()
STAT_CONFIG = os.path.join(BASE_DIR, '.prod')
DEFAULT_CONFIG = os.path.join(BASE_DIR, 'config.ini')
PROD_CONFIG = os.path.join(BASE_DIR, 'config-prod.ini')

# DB
DROP_DB_NAME = 'db.sqlite3'
DROP_DB = os.path.join(DB_DIR, DROP_DB_NAME)
DROP_DB_SCHEMA = os.path.join(SRC_DIR, 'db_schema.sql')
ARG_DEFAULT_MSG = "Drop IP Information"

# App JSON
APP_JSON_NAME = 'app.json'
APP_JSON = os.path.join(BASE_DIR, APP_JSON_NAME)

# Dynamic config loader exporter
if not os.path.exists(STAT_CONFIG):
    CONFIG.read(DEFAULT_CONFIG)
    LOADED_CONFIG = DEFAULT_CONFIG
    SERVER_MODE = 'Standard'
else:
    if os.path.exists(PROD_CONFIG):
        CONFIG.read(PROD_CONFIG)
        LOADED_CONFIG = PROD_CONFIG
        SERVER_MODE = 'Production'

    else:
        print(f'Config-prod does not found, using default config: {DEFAULT_CONFIG}')
        CONFIG.read(DEFAULT_CONFIG)
        LOADED_CONFIG = DEFAULT_CONFIG
        SERVER_MODE = 'Standard'


# Load and export configs from conf.d
def get_config_files():
    d_config_files = []
    d_config_count = 0
    for path in os.listdir(CONF_DIR):
        # check if current path is a file
        if os.path.isfile(os.path.join(CONF_DIR, path)):
            config_path = os.path.join(CONF_DIR, path)
            d_config_files.append(config_path)
            d_config_count += 1
    return d_config_files, d_config_count
    # print(D_CONFIG_FILES)

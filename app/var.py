import os
import configparser
from sys import platform


# Generators
def get_base_dir():
    base = os.path.join(os.getcwd())  # .. means parent directory

    # Return the absolute path of the parent directory
    return os.path.abspath(base)


def get_current_dir():
    return os.path.dirname(os.path.abspath(__file__))


def get_parent_directory():
    # Create a relative path to the parent of the current working directory
    relative_parent = os.path.join(os.getcwd(), "..")  # .. means parent directory

    # Return the absolute path of the parent directory
    return os.path.abspath(relative_parent)


# Vars
APP_ENV = os.getenv("IP2DROP_ENV")

PARENT_DIR = get_parent_directory()
CURR_DIR = get_current_dir()
BASE_DIR = get_base_dir()

# Relative paths
RELATIVE_SRC_DIR = "src/"
RELATIVE_DB_DIR = "db/"
RELATIVE_LOGS_DIR = "logs/"
RELATIVE_CONF_DIR = "conf.d/"
RELATIVE_HELPERS_DIR = "helpers/"

# Configs
CONFIG = configparser.ConfigParser()
STAT_CONFIG = os.path.join(BASE_DIR, '.prod')
DEFAULT_CONFIG = os.path.join(BASE_DIR, 'config.ini')
PROD_CONFIG = os.path.join(BASE_DIR, 'config-prod.ini')

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

DB_DIR = os.path.join(BASE_DIR, RELATIVE_DB_DIR)
SRC_DIR = os.path.join(BASE_DIR, RELATIVE_SRC_DIR)
CONF_DIR = os.path.join(BASE_DIR, RELATIVE_CONF_DIR)
HELPERS_DIR = os.path.join(BASE_DIR, RELATIVE_HELPERS_DIR)
EXPORTED_LOGS_DIR = os.path.join(BASE_DIR, RELATIVE_LOGS_DIR)

# System log
# Detect system/platform
if platform == "linux" or platform == "linux2":
    SYSTEM_LOG = '/var/log/ip2drop.log'
elif platform == "darwin":
    SYSTEM_LOG = os.path.join(EXPORTED_LOGS_DIR, 'ip2drop-script.log')
elif platform == "win32":
    print('Platform not supported. Exit. Bye.')
    exit(1)

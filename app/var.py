import os
import sys
import configparser
from pathlib import Path

# Import app
sys.path.append(str(Path(sys.argv[0]).absolute().parent.parent))
from . import lib

# Vars
APP_ENV = os.getenv("IP2DROP_ENV")

PARENT_DIR = lib.get_parent_directory()
CURR_DIR = lib.get_current_dir()
BASE_DIR = lib.get_up_dir()

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
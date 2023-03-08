import os
import sys
import logging
from pathlib import Path
from sys import platform

sys.path.append(str(Path(sys.argv[0]).absolute().parent.parent))
from . import var

# System log
# Detect system/platform
if platform == "linux" or platform == "linux2":
    SYSTEM_LOG = '/var/log/ip2drop.log'
elif platform == "darwin":
    SYSTEM_LOG = os.path.join(var.EXPORTED_LOGS_DIR, 'ip2drop-script.log')
elif platform == "win32":
    print('Platform not supported. Exit. Bye.')
    exit(1)

# Logging
logging.basicConfig(filename=SYSTEM_LOG,
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%d-%m-%Y %H-%M-%S',
                    level=logging.DEBUG)


# Logger messages
# TODO: Add -v, --verbose as DEBUG mode
def log_debug(msg):
    logging.debug(msg)


def log_info(msg):
    logging.info(msg)


def log_warn(msg):
    logging.warning(msg)


def log_err(msg):
    logging.error(msg)


def log_crit(msg):
    logging.critical(msg)


def msg_info(msg):
    log_info(msg)
    print(msg)
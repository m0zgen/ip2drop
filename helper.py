#!/usr/bin/env python3
# Author: Yevgeniy Goncharov, https://lab.sys-adm.in
# Helper for ip2drop script. Status: testing

# ConfigParser loads the config file and returns a dictionary of the config
# options
import configparser


def load_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


CONFIG = load_config('config.ini')

print(CONFIG['DEFAULT']['EXPORT_COMMAND'])

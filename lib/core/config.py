#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-15 16:04
# @Author  : max
# @FileName: config.py
# @Software: PyCharm

import os
import configparser

PROJECT_PATH = 'E:/PycharmProjects/hunting'
# config('path', 'project_path')
CONFIG_PATH = '{0}/conf.ini'.format(PROJECT_PATH)

__conf = configparser.ConfigParser()
__conf.read(CONFIG_PATH)


def config(section, option):
    return __conf.get(section, option)


MASSCAN_BIN = '{0}/bin/masscan'.format(PROJECT_PATH)
OUTPUT_PATH = '{0}/output'.format(PROJECT_PATH)
WORDLIST_PATH = '{0}/wordlist'.format(PROJECT_PATH)
NMAP_BIN = 'nmap'

# api_url = config('censys', 'api_url')

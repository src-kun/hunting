#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-15 15:39
# @Author  : max
# @FileName: scan.py
# @Software: PyCharm

import os
import time

os.path.abspath(os.path.join(os.getcwd(), "../"))

from lib.base.scan import Masscan, Nmap
from lib.utils.common import md5


def output(result, name=md5(time.time())):
    path = '/tmp/'
    fp = open('{0}{1}.json'.format(path, name), mode='w')
    fp.write(str(result))
    fp.close()


def nmap():
    namp = Nmap()
    output()


def masscan():
    masscan = Masscan()
    print(masscan.scan('192.168.0.102', '22', '--rate=1000'))


nmap()

#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-15 20:42
# @Author  : max
# @FileName: dnsqry.py
# @Software: PyCharm

import os

os.path.abspath(os.path.join(os.getcwd(), "../"))

from lib.base.dnsqry import *


def dnsqery():
    # print(zonetransfer('www.rmlx.cn'))
    print(query('www.rmlx.cn', 'A'))
    print(query2('koudaitong.com', 'cname'))


# print(query2('www.pdflibr.com', 'cname')) cdn
print(query2('mail.0src.com', 'A'))

#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019/10/15 22:19
# @Author  : a
# @FileName: time.py
# @Software: PyCharm

import time


# 格式化成2019-10-15 22:19:13形式
def format_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
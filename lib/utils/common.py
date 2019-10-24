#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-15 19:37
# @Author  : max
# @FileName: comment.py
# @Software: PyCharm

import hashlib


def md5(s):
    m1 = hashlib.md5()
    m1.update(str(s).encode("utf-8"))
    return m1.hexdigest()

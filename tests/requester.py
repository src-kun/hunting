#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-15 22:22
# @Author  : max
# @FileName: requester.py
# @Software: PyCharm
#

import os

os.path.abspath(os.path.join(os.getcwd(), "../"))

from lib.base.requester import Requester


def req_test():
    req = Requester('https://blog.csdn.net/')
    rep = req.request('/weixin_39198406/article/details/78798003')
    print(rep.status)
    print(rep.body)
    print(rep.reason)
    rep = req.request('/weixin_39198406/78798003')
    print(rep.status)
    print(rep.body)
    print(rep.reason)


req_test()

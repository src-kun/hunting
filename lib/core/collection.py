#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019/10/16 10:46
# @Author  : a
# @FileName: collection.py
# @Software: PyCharm

import tldextract

from lib.base.cyberspace import Search
from lib.base.dnsqry import query2

MOUDLE_INDEX = 'collection-'


class Cyberspace:
    INDEX = MOUDLE_INDEX + 'cyberspace'

    @staticmethod
    def search(domain=None, ip=None):
        result = {}
        s = Search(domain, ip)
        sub_doamins = s.sub_domains()

        for sub_doamin in sub_doamins:
            ips = query2(sub_doamin, 'A')
            if ips:
                result[sub_doamin] = ips
        return result

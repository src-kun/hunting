#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-15 23:31
# @Author  : max
# @FileName: collection.py
# @Software: PyCharm

import json
from _socket import gethostbyname

import shodan
from censys import certificates
from lib.base.htmlparse import top_domain_suffix
from lib.core.config import config


class Collection:
    API_URL = config('censys', 'api_url')
    UID = config('censys', 'uid')
    SECRET = config('censys', 'secret')
    api = shodan.Shodan(config('shodan', 'key'))

    def __init__(self, domain=None, ip=None):
        if domain is None and ip is None:
            raise Exception('TODO: error')

        self.ip = ip
        if ip is None:
            self.ip = gethostbyname(domain)

        self.domain = domain
        if self.domain is None:
            self.domain = self.ip_reverse_find_domain

        self.__lookup = None
        self.__sub_domain = None

        self._certificates = certificates.CensysCertificates(self.UID, self.SECRET)

    # TODO ip反查域名
    def ip_reverse_find_domain(self):
        return None

    @property
    def lookup(self):
        if self.__lookup is None:
            self.__lookup = self.api.host(self.ip)
        return self.__lookup

    # 检测是否为cdn
    def is_cdn(self):
        return False

    # 收集子域名
    @property
    def sub_domain(self):
        if self.__sub_domain is None:
            results = []
            for result in self._certificates.search(self.domain, fields=["parsed.__expanded_names"]):
                if 'parsed.__expanded_names' in result:
                    results.extend(result['parsed.__expanded_names'])
            results = list(set(results))
            return [domain for domain in results if not (domain in top_domain_suffix)]
        return self.__sub_domain


cl = Collection(domain='47.93.154.180')
#print(cl.lookup)
#print(cl.sub_domain)

#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019/10/15 20:35
# @Author  : a
# @FileName: discover.py
# @Software: PyCharm


from concurrent.futures import ThreadPoolExecutor

from lib.base.scan import Nmap
from lib.utils.common import md5
from lib.base.requester import Requester
from lib.base.dictionary import Dictionary
from lib.base.dnsqry import zonetransfer, query2

MOUDLE_INDEX = 'discover-'


class WebDirectory(object):
    INDEX = MOUDLE_INDEX + 'webdir'

    def __init__(self, url, filepath, extensions, status_white=[200, 403, 500], max_works=500, **kwargs):
        self.url = url
        self.requester = Requester(url)
        self.wd_tds = []
        self.status = status_white
        self.results = {}
        self.dictionary = Dictionary(filepath, extensions)
        self.max_works = max_works

    def start(self):
        with ThreadPoolExecutor(max_workers=self.max_works) as pool:
            results = pool.map(self.requester.request, self.dictionary.entries)
            for response, url in results:
                if response and response.status in self.status:
                    print(url, response.status)
                    if not (response.status in self.results):
                        self.results[response.status] = []
                    self.results[response.status] = url


class Dns(object):
    result_none_md5 = md5(str({'ips': [], 'mx': [], 'txt': [], 'cname': []}))
    INDEX = MOUDLE_INDEX + 'subdomain'

    def __init__(self, domain, path, max_works=500):
        self.domain = domain
        self.results = {}
        self.dictionary = Dictionary(path)
        self.max_works = max_works

    # 检测结果{'ips': [], 'mx': [], 'txt': [], 'cname': []}是否全为空
    @staticmethod
    def __result_is_none(result):
        return BruteDns.result_none_md5 == md5(str(result))

    def query(self, sub):
        sub_domain = self.domain if sub == '*' else '{0}.{1}'.format(sub, self.domain)

        # A 记录
        return sub_domain, query2(sub_domain, 'A')
        # ipv6 = query2(sub_domain, 'AAAA')
        '''if result['ips']:
            # MX 记录
            result['mx'] = query2(sub_domain, 'MX')

            # TXT 记录
            result['txt'] = query2(sub_domain, 'TXT')

            # CNAME 记录
            result['cname'] = query2(sub_domain, 'CNAME')

        if self.__result_is_none(result):
            result = None
        '''

    def start(self):

        # 检测域传送
        # self.results['zonetransfer'] = (zonetransfer(self.domain))

        # 添加一个空字符，用于检测主域名
        self.dictionary.entries.append('*')

        # 子域名爆破
        with ThreadPoolExecutor(max_workers=self.max_works) as pool:
            results = pool.map(self.query, self.dictionary.entries)
            for sub_domain, ip in results:
                if ip:
                    self.results[sub_domain] = ip


class Port:
    INDEX = MOUDLE_INDEX + 'port'

    @staticmethod
    def nmap(ip, port=None):
        return Nmap().scan(ip, port, '-T4')


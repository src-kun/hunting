#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019/10/16 11:06
# @Author  : a
# @FileName: control.py
# @Software: PyCharm

import re
import time
import json

from lib.core.discover import WebDirectory, Dns, Port
from lib.core.config import WORDLIST_PATH
from lib.core.output import Output
from lib.core.collection import Cyberspace

task_name = 'sungoin'
o = Output(task_name)

domains = ['sungoin.com']

# task = {'task': {'domain': domains}}
#
# for domain in domains:
#     # dns爆破
#     d = Dns(domain, '{0}/subdomains-10000.txt'.format(WORDLIST_PATH))
#     d.start()
#     print(d.results)
#     o.save_subdomain(d.results)
#     # 网络空间搜索
#     results = Cyberspace.search(domain)
#     print(results)
#     o.save_subdomain(results)
#
# o.save_task(task)
# 端口扫描
ips = o.ips
print(ips)

for ip in ips:
    if bool(re.search('[a-z,A-Z]', ip)):
        continue
    print(ip)
    result = Port.nmap(ip)
    print(result)
    o.save_port(ip, result['scan'])
    time.sleep(3)


'''wd = WebDirectory('http://sungoin.com/',
                  '{0}/dicc.txt'.format(WORDLIST_PATH),
                  'php', max_works=100)
wd.start()
o.save_result(WebDirectory.INDEX, wd.results)'''

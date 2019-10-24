#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019/10/16 20:11
# @Author  : a
# @FileName: import.py
# @Software: PyCharm

# !/usr/bin/python3
# -*- coding: utf-8 -*-
#
# @Time    : 2019/10/15 11:23
# @Author  : a
# @FileName: test2.py
# @Software: PyCharm

import lines as lines
from lib.core.output import Output
from lib.core.discover import Dns

o = Output('sungoin')

domains = {}


def domain_ip_map(ip, domain):
    if not (domain in domains):
        domains[domain] = []
    domains[domain].append(ip)


# 根据文件格式解析出域名
def parse(path):
    f = open(path)
    lines = f.readlines()
    ips = []
    l = len(lines)
    for i in range(0, l - 1):
        line = lines[i].replace(' ', '')[:-1]
        if (l - 1) == i:
            line = lines[i].replace(' ', '')
        domain_ip_map(*tuple(line.split('<->')))
    f.close()



parse('C:\\Users\\a\\Desktop\\domains.txt')
o.save_subdomain(domains)
print(domains)
# TODO 服务版本信息

# 重要信息
msg = {'msg': '', 'source': '配置文件', 'ip': '', 'timestamp': '', 'uses': '邮箱登入'}

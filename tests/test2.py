#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019/10/15 11:23
# @Author  : a
# @FileName: test2.py
# @Software: PyCharm

import json
from lib.core.output import Output

o = Output(2)


def parser(text):
    pass


def read_file(path):
    ips = []
    f = open(path)
    lines = f.readlines()
    l = len(lines)
    for i in range(0, l - 1):
        line = lines[i].replace(' ', '')[:-1]
        if (l - 1) == i:
            line = lines[i].replace(' ', '')
        ips.append(tuple(line.split('<->')))
    f.close()
    return ips


result = o.result('{0}-{1}'.format(2, 'collection-cyberspace'))
domains = json.loads(result)
del domains['timestamp']
ips = read_file('C:\\Users\\a\\Desktop\\domains.txt')
for domain in domains:
    for ip, sub_domain in ips:
        if domain in sub_domain:
            domains[domain].append(sub_domain)
print(domains)
domains[domain] = set(domains[domain].copy())
print(result)
print(domains)
# o.save_result(ip, sub_domain)

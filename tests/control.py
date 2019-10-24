#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-28 15:02
# @Author  : max
# @FileName: control.py
# @Software: PyCharm

from urllib.parse import urlparse

from lib.core.brute import BruteDns, WebDirectory
from lib.base.spider import *
from lib.core.output import Output
from lib.core.config import WORDLIST_PATH

o = Output()


def start(url):
    extract_result = tldextract.extract(url)
    top_domain = '{0}.{1}'.format(extract_result.domain, extract_result.suffix)
    domain = urlparse(url).netloc
    print(top_domain, domain)
    bdns = BruteDns(top_domain, '{0}/2.txt'.format(WORDLIST_PATH), output=o)
    bdns.start()
    o.result['']
    from lib.base.scan import Masscan, Nmap


start('http://www.wecaisport.com/')
o.save()


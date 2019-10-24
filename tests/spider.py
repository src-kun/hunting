#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-18 12:03
# @Author  : max
# @FileName: spider.py
# @Software: PyCharm

import json
import os
os.path.abspath(os.path.join(os.getcwd(), "../"))

from lib.base.spider import Spider
from lib.base.htmlparse import HtmlParse

sp = Spider('http://message.ckefu.com/manager/', deep=3)
sp.start()
print(json.dumps(sp.results, sort_keys=True, indent=2))


'''hps = HtmlParse(html)
print(hps.title())
print(hps.a_label())
print(hps.img_label())
print(hps.script_label())
print(hps.link_label())
'''
#print(HtmlParse.is_static('http://baidu.com/2.gxt'))
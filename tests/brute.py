#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-25 13:31
# @Author  : max
# @FileName: brute.py
# @Software: PyCharm

import os
import warnings

warnings.filterwarnings("ignore")
os.path.abspath(os.path.join(os.getcwd(), "../"))

from lib.core.brute import WebDirectory, BruteDns
from lib.core.config import WORDLIST_PATH
from lib.core.output import Output


o = Output(1)


wd = WebDirectory('https://www.singulato.com/',
                  '{0}/test2.txt'.format(WORDLIST_PATH),
                  'php', o=o, max_works=100)
wd.start()

bdns = BruteDns('sunke.com', '{0}/test.txt'.format(WORDLIST_PATH), o=o)
bdns.start()
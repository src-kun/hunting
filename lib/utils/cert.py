#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-27 10:13
# @Author  : max
# @FileName: cert.py
# @Software: PyCharm

import ssl
import OpenSSL


def get_domain_by_cert(addr):
    cert = ssl.get_server_certificate((addr, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    print(x509.get_subject().get_components())


print(get_domain_by_cert('www.csdn.net'))

#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-26 20:22
# @Author  : max
# @FileName: get_https_cert.py
# @Software: PyCharm

# !/usr/bin/python
# -*- coding: utf-8 -*-
from socket import socket
import ssl
import json
import M2Crypto
import OpenSSL

# M2Crypto
cert = ssl.get_server_certificate(('www.csdn.net', 443))
x509 = M2Crypto.X509.load_cert_string(cert)
print(x509.get_subject().as_text())
# 'C=US, ST=California, L=Mountain View, O=Google Inc, CN=www.google.com'

# OpenSSL
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
print(x509.get_issuer().get_components())
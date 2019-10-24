#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-26 15:13
# @Author  : max
# @FileName: tmp.py
# @Software: PyCharm
import socket  # 导入 socket 模块

s = socket.socket()  # 创建 socket 对象
host = 'www.csdn.net'  # 获取本地主机名
port = 443  # 设置端口号
# www.csdn.net
s.connect((host, port))
print(s.recv(1024))
s.close()
#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019/10/22 23:33
# @Author  : a
# @FileName: readfile.py
# @Software: PyCharm
import json
from datetime import datetime
import xlrd
import xlwt

wb = xlwt.Workbook()
ws = wb.add_sheet('A Test Sheet2')


def test():
    i = 0
    ws.write(0, 0, '手机号')
    ws.write(0, 1, '平台')

    with open('C:\\Users\\a\\Desktop\\res (2).txt', "r", encoding='UTF-8') as f:
        for line in f:
            if len(line) > 10000:
                rows = json.loads(line.replace('\n', ''))['data']['rows']
                for row in rows:
                    i += 1
                    ws.write(i, 0, row['phone'])
                    ws.write(i, 1, row['channels_name'])

                break
    wb.save('C:\\Users\\a\\Desktop\\example.xls')

test()

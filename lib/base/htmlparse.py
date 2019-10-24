#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-16 11:18
# @Author  : max
# @FileName: htmlparse.py
# @Software: PyCharm

import re
import warnings
warnings.filterwarnings('ignore')
from bs4 import BeautifulSoup
from urllib.parse import urlparse

exclude = ['javascript:;', '#']

# url所有后缀
suffix = ['html', 'htm', 'shtml', 'css', 'xml', 'gif', 'jpeg', 'jpg', 'js', 'atom',
          'rss', 'mml', 'txt', 'jad', 'wml', 'htc', 'png', 'svg', 'svgz', 'tif',
          'tiff', 'wbmp', 'webp', 'ico', 'jng', 'bmp', 'woff', 'woff2', 'jar', 'war',
          'ear', 'json', 'hqx', 'doc', 'pdf', 'ps', 'eps', 'ai', 'rtf', 'm3u8', 'kml',
          'kmz', 'xls', 'eot', 'ppt', 'odg', 'odp', 'ods', 'odt', 'pptx', 'docx', 'wmlc',
          '7z', 'cco', 'jardiff', 'jnlp', 'run', 'pl', 'pm', 'prc','pdb', 'rar', 'rpm',
          'sea', 'swf', 'sit', 'tcl', 'tk', 'der', 'pem', 'crt', 'xpi', 'xhtml', 'xspf',
          'zip', 'bin', 'exe', 'dll', 'deb', 'dmg', 'iso', 'img', 'msi', 'msp', 'msm',
          'mid', 'midi', 'kar', 'mp3', 'ogg', 'm4a', 'ra', '3gpp', '3gp', 'ts', 'mp4',
          'mpeg', 'mpg', 'mov', 'webm', 'flv', 'm4v', 'mng', 'asx', 'asf', 'wmv', 'avi']

# url静态文件后缀
static_suffix = ['apk', 'css', 'xml', 'gif', 'jpeg', 'jpg', 'js', 'atom', 'rss',
                 'mml', 'txt','jad', 'wml', 'htc', 'png', 'svg', 'svgz', 'tif',
                 'tiff','wbmp', 'webp', 'ico', 'jng', 'bmp', 'woff', 'woff2',
                 'jar', 'war', 'ear','hqx', 'doc', 'pdf', 'ps', 'eps', 'ai',
                 'rtf', 'm3u8', 'kml', 'kmz', 'xls', 'eot', 'ppt','odg', 'odp',
                 'ods', 'odt', 'pptx', 'docx', 'wmlc', '7z', 'cco', 'jardiff',
                 'jnlp', 'run', 'pl', 'pm', 'prc','pdb', 'rar','rpm', 'sea', 'swf',
                 'sit', 'tcl', 'tk', 'der', 'pem', 'crt', 'xpi', 'xhtml', 'xspf',
                 'zip', 'bin', 'exe', 'dll', 'deb', 'dmg', 'iso', 'img', 'msi', 'msp',
                 'msm', 'mid', 'midi', 'kar', 'mp3', 'ogg', 'm4a', 'ra', '3gpp', '3gp',
                 'ts', 'mp4', 'mpeg', 'mpg', 'mov', 'webm', 'flv', 'm4v', 'mng', 'asx',
                 'asf', 'wmv', 'avi']

# 顶级域名后缀
top_domain_suffix = ('com', 'la', 'io', 'co', 'info', 'net', 'org', 'me', 'cn',
                     'mobi', 'us', 'biz', 'xxx', 'ca', 'co.jp', 'com.cn',
                     'net.cn', 'org.cn', 'mx', 'tv', 'ws', 'ag', 'com.ag',
                     'net.ag', 'org.ag', 'am', 'asia', 'at', 'be', 'com.br',
                     'net.br', 'bz', 'com.bz', 'net.bz', 'cc', 'com.co', 'net.co',
                     'nom.co', 'de', 'es', 'com.es', 'nom.es', 'org.es', 'eu',
                     'fm', 'fr', 'gs', 'in', 'co.in', 'firm.in', 'gen.in', 'ind.in',
                     'net.in', 'org.in', 'it', 'jobs', 'jp', 'ms', 'com.mx', 'nl',
                     'nu', 'co.nz', 'net.nz', 'org.nz', 'se', 'tc', 'tk', 'tw',
                     'com.tw', 'idv.tw', 'org.tw', 'hk', 'co.uk', 'me.uk', 'org.uk', 'vg')
class HtmlParse(object):

    def __init__(self, text):
        self.__text = text
        self.soup = BeautifulSoup(text)

    @staticmethod
    def is_url(url):
        if url:
            if re.match(r'^https?:/{2}\w.+$', url):
                return True
            elif url[0] == '/':
                return True
        return False

    @staticmethod
    def is_static(url):
        u_parse = urlparse(url)
        index = u_parse.path.rfind('.') + 1
        if index and u_parse.path[index:] in static_suffix:
            return True
        return False

    def select_label(self, label, e = 'src'):
        urls = []
        for u in self.soup.find_all(label):
            url = u.get(e)
            if HtmlParse.is_url(url):
                urls.append(url)
        return urls

    @property
    def title(self):
        return self.soup.title.string

    @property
    def a_label(self):
        return self.select_label('a', 'href')

    @property
    def img_label(self):
        return self.select_label('img')

    @property
    def script_label(self):
        return self.select_label('script')

    @property
    def link_label(self):
        return self.select_label('link', 'href')

    @property
    def urls(self):
        urls = []
        urls.extend(self.a_label)
        urls.extend(self.img_label)
        urls.extend(self.script_label)
        urls.extend(self.link_label)
        return urls
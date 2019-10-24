#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-16 11:14
# @Author  : max
# @FileName: spider.py
# @Software: PyCharm

from copy import deepcopy
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import requests
import tldextract
import pybloom_live
from lib.base.htmlparse import HtmlParse


class Spider:
    headers = {
        'User-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Keep-Alive': '300',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
    }

    def __init__(self, url, deep=4, thread_num=100,
                 url_beyond=100, suspend=5, timeout=5,
                 capacity=1000000, error_rate=0.001):

        # 爬虫起始url
        self._url = url
        if url.endswith('/'):
            self._url = url[:-1]

        # 顶级域名
        self.top_domain = tldextract.extract(url).domain
        # 所有爬取到url
        self.__urls_dict = {}

        # 临时存储URL数据 {'url链接':[此链接中提取到的URL]}
        self._urls_dict_tmp = {}
        self.urls_dict_tmp = url

        # 爬虫深度
        self.deep = deep
        self.bloom = pybloom_live.BloomFilter(capacity=capacity, error_rate=error_rate)

        self._req_tds = []

        # 超出个数时暂停
        self.url_beyond = url_beyond
        # 暂停时间
        self.suspend = suspend
        # 线程数
        self.thread_num = thread_num
        # 请求超时时间
        self.timeout = timeout

    @property
    def results(self):
        return self.__urls_dict

    @property
    def urls_dict_tmp(self):
        for urls_dict_key in self._urls_dict_tmp:
            yield (urls_dict_key, self._urls_dict_tmp[urls_dict_key])
        self._urls_dict_tmp.clear()

    @urls_dict_tmp.setter
    def urls_dict_tmp(self, url):
        if isinstance(url, dict):
            self._urls_dict_tmp.update(deepcopy(url))
        elif isinstance(url, str):
            self._urls_dict_tmp = {url: [url]}
        else:
            raise Exception('TODO: url type error')

    def __filter(self, url):

        # 过滤非本域名资源
        u_parse = urlparse(url)
        if not (self.top_domain in u_parse.netloc):
            return True

        # 过滤重复
        if url in self.bloom:
            return True

        return False

    def request(self, url):
        try:
            self.headers['Referer'] = url
            return url, requests.get(url, headers=self.headers, timeout=self.timeout)
        except requests.exceptions.ReadTimeout:
            print('TODO: request time out!')
        except requests.exceptions.ConnectTimeout:
            print("TODO: connect timeout!")
        except UnicodeEncodeError:
            print('TODO: UnicodeEncodeError!')
        except requests.exceptions.ConnectionError:
            print('TODO: connect server timeout!')
        except requests.exceptions.ChunkedEncodingError:
            pass
        except Exception as e:
            print('TODO: ' + str(e))

    # 解析线程返回的结果
    def _parser(self, current_page_url, results):
        for result in results:
            # 线程返回None
            (page_url, response) = (None, None) if result is None else result
            # response == None 继续循环结果
            if response is None:
                continue

            try:
                u_parse = urlparse(current_page_url)
                hp = HtmlParse(response.text)
                for url in hp.urls:
                    # 去掉最后的 /
                    if url.endswith('/'):
                        url = url[:-1]

                    # 为缺少http[s]的添加协议
                    if url.startswith('//'):
                        url = '{scheme}:{url}'.format(scheme = u_parse.scheme, url=url)
                    elif url.startswith('/'):  # 拼接相对url
                        url = '{scheme}://{netloc}{path}'.format(scheme=u_parse.scheme, netloc=u_parse.netloc, path=url)

                    # 拦截不必要url
                    if self.__filter(url):
                        continue

                    yield page_url, url
            except Exception as e:
                print('TODO: ' + str(e))
                yield None, None

    def start(self):
        # 当前深度的url数组
        current_deep_urls = {}
        # 页面所有url
        results = []

        with ThreadPoolExecutor(max_workers=self.thread_num) as pool:
            for i in range(0, self.deep + 1):
                for current_page_url, urls_tmp in self.urls_dict_tmp:
                    results = pool.map(self.request, urls_tmp)
                    for page_url, url in self._parser(current_page_url, results):

                        if url is None:
                            continue

                        # 将url加入bloom
                        self.bloom.add(url)

                        if (page_url in current_deep_urls) is False:
                            current_deep_urls[page_url] = []
                            self.__urls_dict[page_url] = []

                        # 过滤掉静态文件
                        if HtmlParse.is_static(url) is False:
                            current_deep_urls[page_url].append(url)

                        self.__urls_dict[page_url].append(url)

                self.urls_dict_tmp = current_deep_urls
                # print('deep：{0} {1}'.format(i, json.dumps(current_deep_urls, sort_keys=True, indent=2)))
                # print('deep：{0}'.format(i))
                current_deep_urls.clear()
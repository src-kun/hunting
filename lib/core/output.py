#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-25 13:43
# @Author  : max
# @FileName: output.py
# @Software: PyCharm

import json

from redis import Redis

from lib.core.config import OUTPUT_PATH
from lib.utils.time import format_time
from lib.utils.common import md5


class Task:
    def __init__(self, task_name):
        pass

    def save(self):
        pass

    def add(self):
        pass

    def resulsts(self):
        pass

    def update(self):
        pass


class Output():
    '''
    task_name 任务id，区分任务
    '''

    def __init__(self, task_name=None):
        self.__task = Redis(host='192.168.234.128', port=6379, db=0, decode_responses=True)
        self.__results = Redis(host='192.168.234.128', port=6379, db=1, decode_responses=True)
        self.__results_pipe = self.__results.pipeline()
        self.task_name = task_name

    def _format_task_index(self, mod):
        return '{0}-{1}'.format(self.task_name, mod.INDEX)

    def save_task(self, task):
        self.__task.lpush(self.task_name, json.dumps(task))

    @property
    def ips(self):
        key = '{0}-ips'.format(self.task_name)
        if self.__results.exists(key):
            return self.__results.smembers(key)

    def _sadd_domains_ips(self, sub_domain, ips):
        self.__results_pipe.sadd('{0}-sub_domains'.format(self.task_name), sub_domain)
        self.__results_pipe.sadd('{0}-ips'.format(self.task_name), *ips)

    def save_subdomain(self, sub_domains):
        for sub_domain in sub_domains:
            self._sadd_domains_ips(sub_domain, sub_domains[sub_domain])
            if self.__results.exists(sub_domain):
                ips = json.loads(self.__results.get(sub_domain))
                sub_domains[sub_domain].extend(ips)
                sub_domains[sub_domain] = list(set(sub_domains[sub_domain]))
            self.__results_pipe.set(sub_domain, json.dumps(sub_domains[sub_domain]))
        self.__results_pipe.execute()

    def save_port(self, ip, result):
        self.__results.set(ip, json.dumps(result))
    # def subdomains(self):
    #     pass
    #
    # def results(self, mod, start=0, end=-1):
    #     key = self._format_task_index(mod)
    #     if self.__r.exists(key):
    #         return self.__r.lrange(self._format_task_index(mod), start, end)
    #
    # # mod.INDEX 模块index
    # def result(self, mod, index=0):
    #     key = self._format_task_index(mod)
    #     if self.__r.exists(key):
    #         return json.loads(self.__r.lindex(self._format_task_index(mod), index))
    #
    # def update(self, mod, result, index=0):
    #     key = self._format_task_index(mod)
    #     if not self.__r.exists(key):
    #         raise Exception('task {} not found!'.format(self._format_task_index(mod)))
    #     result['timestamp'] = format_time()
    #     result = json.dumps(result)
    #     return self.__r.lset(self._format_task_index(mod), index, result)

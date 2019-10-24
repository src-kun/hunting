#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-15 20:45
# @Author  : max
# @FileName: dnsqry.py
# @Software: PyCharm

# !/usr/bin/python
# -*- coding: utf-8 -*-
import socket

''' set the default timeout on sockets to 5 seconds '''
if hasattr(socket, 'setdefaulttimeout'): socket.setdefaulttimeout(5)
from socket import gethostbyname

import dns
import requests
from dns.zone import from_xfr
from dns.resolver import Resolver
from dnslib import DNSRecord, RCODE, QTYPE

query_types = ['TA', 'A', 'NS', 'CNAME', 'SOA', 'CAA', 'PTR', 'MX', 'TXT', 'RP', 'AFSDB', 'SPF', 'DLV', 'SIG', 'KEY',
               'AAAA', 'LOC', 'SRV', 'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY',
               'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'TKEY', 'TSIG', 'IXFR', 'AXFR',
               'ANY']


def query(domain, query_type, timeout=5.0):
    answers = []
    res_list = []
    resl = Resolver()
    resl.timeout = timeout
    resl.lifetime = 2.0

    try:
        answers = resl.query(domain, query_type)
    except Exception as e:
        pass

    for dns_domain in answers:
        try:
            res_list.append(str(dns_domain).rstrip('.'))
        except socket.gaierror as e:  # skip non resolvable name server
            pass

    return res_list


def query2(domain, query_type, dns_server='8.8.8.8', tcp=False, dns_port=53, timeout=5):
    res_list = []

    try:
        gethostbyname(dns_server)
    except ValueError as e:
        raise Exception('DNS Address Error: %s' % dns_server)

    query = DNSRecord.question(domain, query_type)
    try:
        answers = DNSRecord.parse(query.send(dns_server, dns_port, tcp=tcp, timeout=timeout))
        if answers:
            rcode = RCODE[answers.header.rcode]
            for r in answers.rr:
                try:
                    rtype = str(QTYPE[r.rtype])
                except:
                    rtype = str(r.rtype)
                res_list.append(str(r.rdata).rstrip('.'))
    except socket.timeout:
        print('TDOD: socket timeout!')
    except Exception as e:
        print('TODO:' + str(e), domain, query_type)
    return res_list


# dns domain zone transfer
def zonetransfer(target):

    zonetransfer_list = []

    ns_list = query(target, 'NS')
    for ns in ns_list:
        zone = None
        try:
            zone = from_xfr(dns.query.xfr(ns, target))
        except Exception as e:
            pass

        if zone:
            for name, node in zone.nodes.items():
                for record in node.rdatasets:
                    name = str(name)
                    if name != '@' and name != '*':
                        zonetransfer_list.append(name + '.' + target)

    if zonetransfer_list:
        return list(set([item.lower() for item in zonetransfer_list]))
    return zonetransfer_list

# print(query2('www.aliyun.com', 'cname'))

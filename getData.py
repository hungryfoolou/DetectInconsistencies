#!/usr/bin/env python3
#coding: utf-8

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from bs4 import BeautifulSoup
import os.path
'''
功能：一些简单的数据处理
'''

CIPHERS = (
    'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
    'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5'
)
class DESAdapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables 3DES support in Requests.
    """
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)


# 获取页面，通过这种方式获取页面可避免SSL error
def get_page(link):
    s = requests.Session()
    s.mount(link, DESAdapter())
    page = s.get(link, timeout=60, headers={'User-Agent': "Magic Browser"})
    return page


# 获取BeautifulSoup的页面
def get_pagecontent(link):
    page = get_page(link)
    page_content = BeautifulSoup(page.content).get_text()
    return page_content

# 把大的cve_ref文件切分成小的cve_ref文件（按照年份），程序没有保留最后一年（2019）的数据（2019年的CVE的ref都是空的，没必要保留）
def get_small_cve_ref():
    file_path = 'cve_ref/'  # 原始数据的目录
    try:
        path_dir = os.listdir(file_path)  # 获取目录下的文件
        for all_dir in path_dir:  # 遍历文件
            child = os.path.join('%s\%s' % (file_path, all_dir))  # 获取文件的完整的路径
            if os.path.isfile(child):
                with open(child,'r',encoding='UTF-8') as f:  # 打开文件
                    lines = f.readlines()  # 获取文件的所有行
                    year = 1999  # 从1999年开始
                    start_line = 0
                    line_cnt = 0  # 文件行数
                    for line in lines:
                        line_cnt = line_cnt + 1
                        if line.find('CVE-'+ str(year+1)) != -1:  # 找到下一年的数据了，接下来保存本年的数据
                            new_lines = lines[start_line:line_cnt-1]
                            new_dir = str(year) + '_' + all_dir
                            new_file_path = os.path.join('%s\%s' % (file_path, new_dir))
                            with open(new_file_path, 'w', encoding='utf-8') as newf:
                                for new_line in new_lines:
                                    newf.write(new_line)
                            start_line = line_cnt-1
                            year = year + 1
                break  # 只遍历一个大的cve_ref文件
    except Exception as ex:
        print(ex)
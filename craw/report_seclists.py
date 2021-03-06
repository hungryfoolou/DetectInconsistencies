#!/usr/bin/env python3
#coding: utf-8

from lxml import html
from getData import get_page
'''
功能：爬取seclists的信息
'''


# 爬取seclists的title
def craw_title_seclists(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write

    # 查看源代码而非F12获取xpath
    title_section = tree.xpath('string(/html/body/table[2]/tr[1]/td[2]/table/tr/td/font[1]/b)')
    if len(title_section) > 0:
        dict_to_write[cve_id]['seclists'][link] = {}  # 要初始化，由于先执行craw_title_seclists函数，所以在该处初始化
        title1 = title_section.strip()
        dict_to_write[cve_id]['seclists'][link]['title'] = title1
    else:
        print('seclists error ' + link)
    return dict_to_write


# 爬取seclists的content
def craw_content_seclists(cve_id, link, dict_to_write, tree):
    dict_to_write = dict_to_write

    # 通过源代码而非F12获得xpath
    content_section = tree.xpath('string(/html/body/table[2]/tr[1]/td[2]/table/tr/td/pre)')
    if len(content_section) > 0:
        content_section = content_section.strip()
        dict_to_write[cve_id]['seclists'][link]['content'] = content_section
    else:
        print('seclists error ' + link)
    return dict_to_write


# 爬取seclists的多种信息
def craw_report_seclists(cve_id, link, dict_to_write):
    dict_to_write = dict_to_write

    page = get_page(link)
    print(link)
    tree = html.fromstring(page.content)

    # 获取seclists的title
    dict_to_write = craw_title_seclists(cve_id, link, dict_to_write, tree)

    # 获取seclists的content
    dict_to_write = craw_content_seclists(cve_id, link, dict_to_write, tree)

    return dict_to_write
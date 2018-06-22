#!/usr/bin/env python
#coding=utf-8

from django import template
from django.utils.safestring import mark_safe
from django.template.base import Node, TemplateSyntaxError
import json
 
register = template.Library()
 
@register.simple_tag
def mymethod(v1):
    return  v1 * 1000

'''
@register.simple_tag
def my_input(id,arg):
    result = "<input type='text' id='%s' class='%s' />" %(id,arg,)
    return mark_safe(result)
'''

@register.simple_tag
def mymethod2(v1):
    if v1 == 1:
        return '超级管理员'
    else:
        return '普通管理员'

@register.simple_tag
def get_rule_index_name(v1):
    rule_index_name = (u'无响应',u'CPU使用率', u'内存使用率',u'磁盘Inode',u'磁盘空间',u'磁盘IOPS',u'发送流量',u'连接数',u'接收流量')
    result = rule_index_name[v1]
    return result

@register.simple_tag
def get_rule_index_triggers_times(v1):
    rule_index_triggers_times = ('连续1次','连续3次','连续5次','连续10次','连续15次','连续30次')
    return rule_index_triggers_times[v1]

@register.simple_tag
def get_triggers_diff(v1):
    triggers_diff = (' >= ', ' > ', ' <= ', ' < ', ' = ', ' != ')
    return triggers_diff[v1]

@register.simple_tag
def myjson(v1):
    return json.loads(v1)

@register.simple_tag
def mylen(v1):
    return len(v1)

@register.simple_tag
def get_hosts(v1,v2):
    result = v1.get(v2,"")
    return ",".join(result)

@register.simple_tag
def get_warning_message(v1):
    if v1 > 0:
        return "<span style='color:red'>异常</span>"
    else:
        return "<span style='color:green'>正常</span>"
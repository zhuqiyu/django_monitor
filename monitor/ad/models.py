# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
import django
import hashlib
# Create your models here.


#class UserType(models.Model):


class UserInfo(models.Model):
    user_type_choice = (
    (int(0), u'普通管理员'),
    (int(1), u'超级管理员'),
    )
    user_type = models.IntegerField(choices=user_type_choice)
    name = models.CharField(max_length=30,unique=True)
    password = models.CharField(max_length=256)
    salt = models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Salt',null=True)
    # hash = hashlib.md5()
    # hash.update(password)
    # password = hash.hexdigest()
    email = models.EmailField()
    memo = models.TextField(null=True)
    #typeId = models.ForeignKey('UserType')
    atime = models.DateTimeField(auto_now=True)
    ctime= models.DateTimeField(auto_now_add=True)
    
    def __unicode__(self):
        return self.name


class Salt(models.Model):
    value = models.BinaryField(max_length=256)



class UserGroup(models.Model):
    Name = models.CharField(max_length=50)


'''    
class User(models.Model):
    Name = models.CharField(max_length=50)
    Email = models.EmailField(max_length=30)
    group_relation = models.ManyToManyField('UserGroup')

'''

  
class Asset(models.Model):
    hostname = models.CharField(max_length=30, unique=True)
    ip = models.GenericIPAddressField(unique=True)
    user_group = models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='UserGroup')
    create_date = models.DateTimeField(auto_now_add=True)
    update_date = models.DateTimeField(auto_now=True)
    hostgroup = models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='HostGroup', default=1)


# monitor models
# 下面是监控相关model


class HostGroup(models.Model):
    name = models.CharField(max_length=32,unique=True)
    #templates = models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Templates')
    templates = models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Templates')
    memo = models.TextField(u"备注",blank=True,null=True)
    def __unicode__(self):
      return self.name


class Templates(models.Model):
    name = models.CharField(max_length=32,unique=True)
    #triggers = models.ManyToManyField('Triggers', verbose_name=u"触发器列表", blank=True)
    # triggers_choice = (
    # (int(0), u'普通管理员'),
    # (int(1), u'超级管理员'),
    # )
    triggers = models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Triggers')
    memo = models.TextField(max_length=64)


class Triggers(models.Model):
    name = models.CharField(max_length=32, unique=True)
    # triggers_index = models.IntegerField()
    # rule = models.IntegerField()
    memo = models.TextField(u"备注",blank=True,null=True)
    def __unicode__(self):
      return self.name


# class TriggersIndex(models.Model):
#     name = models.CharField(max_length=32, unique=True)
#     templates = models.IntegerField()


# class Rule(models.Model):
#     name = models.CharField(max_length=32)
#     rule_index = models.IntegerField()
#     memo = models.TextField(max_length=64)


class RuleIndex(models.Model):
    name_choice = (
        (int(0), u'无响应'),
        (int(1), u'CPU使用率'),
        (int(2), u'内存使用率'),
        (int(3), u'磁盘Inode'),
        (int(4), u'磁盘空间'),
        (int(5), u'磁盘IOPS'),
        (int(6), u'发送流量'),
        (int(7), u'连接数'),
        (int(8), u'接收流量'),
    )
    name = models.IntegerField(choices=name_choice)
    triggers = models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Triggers')
    time_choice = (
        (int(1), u'1分钟'),
    )
    time = models.IntegerField(choices=time_choice)
    triggers_times_choice = (
        (int(0), u'连续1次'),
        (int(1), u'连续3次'),
        (int(2), u'连续5次'),
        (int(3), u'连续10次'),
        (int(4), u'连续15次'),
        (int(5), u'连续30次'),
    )
    triggers_times = models.IntegerField(choices=triggers_times_choice)
    triggers_diff_choice = (
        (int(0), u'>='),
        (int(1), u'>'),
        (int(2), u'<='),
        (int(3), u'<'),
        (int(4), u'='),
        (int(5), u'!='),
    )
    triggers_diff = models.IntegerField(choices=triggers_diff_choice)
    triggers_value = models.IntegerField()
    warning = models.IntegerField(default=0)

class RuleResult(models.Model):
    time = models.DateTimeField()
    data = models.TextField()
    host = models.CharField(max_length=30)


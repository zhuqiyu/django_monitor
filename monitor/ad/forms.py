#!/usr/bin/env python
# coding=utf-8

from django import forms
from . import models

'''
class RegisterForm(forms.Form):
    name = forms.CharField()
    password = forms.CharField()
    email = forms.EmailField(required=True,error_messages={'invalid':'邮箱格式不合法'})
    memo = forms.CharField()
    typeId = forms.ChoiceField()
'''


class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = models.UserInfo
        fields = ('name', 'password', 'email', 'memo', 'user_type')
        widgets = {
            'password': forms.PasswordInput(attrs={'type': 'password'})
        }


class AssetListForm(forms.Form):
    usergroup_choice = (
        (int(1), u'运维组'),
        (int(2), u'开发组'),
        (int(3), u'DBA组'),
    )
    hostname = forms.CharField(max_length=30)
    ip = forms.GenericIPAddressField()
    user_group = forms.IntegerField(widget=forms.widgets.Select(choices=usergroup_choice))


class RuleIndexForm(forms.ModelForm):
    # password = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = models.RuleIndex
        fields = ('name', 'triggers', 'time', 'triggers_times',
                  'triggers_diff', 'triggers_value', 'switch')


'''
class AssetListForm(forms.ModelForm):
    class Meta:
        usergroup_choice = (
            (int(1),u'运维组'),
            (int(2),u'开发组'),
            (int(3),u'DBA组'),
        )
        model = models.Asset
        fields = ('hostname','ip',)
        #widgets = {
        #    'user_group' : forms.Select(choices=usergroup_choice),
        #}
        widgets = {
            'user_group':forms.widgets.Select(choices=usergroup_choice),
        }
        #help_texts = {'user_group':(u'运维组/开发组/DBA组'),}
'''


# class RegisterForm2(forms.Form):
#     user_type_choice = (
#         (1, u'普通管理员'),
#         (2, u'超级管理员'),
#         )
#     user_type = forms.IntegerField(widget=forms.widgets.Select(choices=user_type_choice,
#                                                                attrs={'class': "form-control"}))


'''
class RegisterForm2(forms.ModelForm):
    class Meta:
        model = models.UserInfo
        fields = ('typeId',)
'''
'''
        fields = ('name','password','email','memo','typeId')
'''

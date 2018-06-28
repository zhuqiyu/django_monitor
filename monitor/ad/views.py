# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect
from .models import (UserInfo, Salt, UserGroup, Asset, HostGroup,
                     Templates, Triggers, RuleIndex, RuleResult)

# Create your views here.

from .forms import RegisterForm, AssetListForm, RuleIndexForm
from django.http.response import HttpResponse
from .Authcode import authCode
import logging
import json
import os
import time
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import telnetlib
import hashlib


def login(request):
    """ 登录函数
    结果: 跳转到assetlist
    """
    result = ''
    '''
    hash = hashlib.md5()
    hash.update(raw_input('请输入密码: '))
    passwd = hash.hexdigest()
    '''
    if request.session.get('username', None):
        user = request.session.get('name', None)
        return render(request, 'login2.html', {'user': user})
    if request.method == 'POST':
        user = request.POST.get('username', None)
        pwd = request.POST.get('password', None).encode("utf-8")
        # pwd_md5 = request.POST.get('', None)
        acode = request.POST.get('auth_code_client', None)
        is_empty = all([user, pwd, acode, request.session["verify_code"]])
        print(user, pwd, acode, request.session["verify_code"])
        print(request)

        if is_empty is False:
            result = '用户名/密码不能为空'
            return render(request, 'login.html', result)
        elif acode == request.session["verify_code"]:
            salt = UserInfo.objects.get(name=user).salt.value
            # salt = Salt.objects.filter(id=salt_id)[0].value
            print("salt_id", salt)
            print(type(salt), salt)
            if len(pwd) != 32:
                pwd = hashlib.md5(pwd).hexdigest().encode("utf-8")
            print(type(pwd), pwd)
            salt_password = salt + pwd
            print(salt_password)
            pwd = hashlib.md5(salt_password).hexdigest()
            print(pwd)
            if UserInfo.objects.filter(name=user, password=pwd).count() >= 1:
                admin_level = UserInfo.objects.get(name=user).user_type
                if admin_level == 1:
                    request.session['username'] = "superadmin"
                    request.session.set_expiry(6000)
                else:
                    request.session['username'] = "admin"
                    request.session.set_expiry(6000)
                request.session["name"] = user
                return redirect('/ad/assetlist')
                # return HttpResponse('登录成功')
            else:
                result = '用户名/密码错误'
                return render(request, 'login.html', {'status': result})
        else:
            result = '验证码错误'
            return render(request, 'login.html', {'code_status': result})
    else:
        return render(request, 'login.html', {'status': result})


def ad_exit(request):
    # 登出
    """
    :return: sign out
    """
    request.session["username"] = None
    return redirect("/ad/login/")


def auth(request):
    """ 验证码函数 ,authCode类来自Authcode.py
    @:return
        auth_code_img, 二进制图片
    """
    auth_code = authCode()
    auth_code_img = auth_code.gene_code()
    auth_code_text = auth_code.text
    # cache.set("verify_code", auth_code_text,60)   # auth_code_text
    request.session["verify_code"] = auth_code_text
    return HttpResponse(auth_code_img, 'image/png')


def Register(request):
    """ 注册函数 """
    result = ''
    registerForm = RegisterForm()
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        # print form
        if form.is_valid():
            # data = form.clean()
            name = request.POST.get("name", None)
            password = request.POST.get("password", None).encode("utf-8")
            email = request.POST.get("email", None)
            memo = request.POST.get("memo", None)
            user_type = request.POST.get("user_type", None)
            print(name, password, email, memo, user_type)
            if UserInfo.objects.filter(name=name).count():
                result = '用户名已存在'
                return render(request, 'register.html',
                              {'form': registerForm, 'status': result})
            else:
                try:
                    # 加盐
                    salt = os.urandom(12)
                    if len(password) != 32:
                        password = hashlib.md5(password).hexdigest().encode("utf-8")
                    salt_password = salt + password
                    print(salt_password)
                    password = hashlib.md5(salt_password).hexdigest()
                    salt_id = Salt.objects.create(value=salt).id
                    UserInfo.objects.create(user_type=user_type, name=name, password=password,
                                            email=email, memo=memo, salt_id=salt_id)
                    # form.save()
                    return redirect('/ad/login/')
                except Exception as e:
                    logging.error("form.save()", e)
                    return render(request, 'register.html', {'form': registerForm, 'status': result})
            # form.save()
        else:
            # print form.errors.as_json()
            result = '无效的用户名/密码'
    return render(request, 'register.html',
                  {'form': registerForm, 'status': result})


def AssetUpdate(request):
    """
    资产配置修改
    :request: user login
    :return: httpresponse('ok')
    """
    if not request.session.get('username', 0):
        return redirect('/ad/login/')
    if request.method == 'POST':
        # print request.POST.get('data')
        Hostname = request.POST.get('hostname', None)
        Ip = request.POST.get('ip', None)
        Id = request.POST.get('id', None)
        # is_empty = all([Hostname,Ip])
        # print Id,Ip,Hostname
        if Hostname and Ip:
            print('Hostname', Hostname)
            print('ip', Ip)
            obj = Asset.objects.get(id=Id)
            obj.hostname = Hostname
            obj.ip = Ip
            try:
                obj.save()
                print("ok")
            except Exception as e:
                logging.error(e)
                return HttpResponse("主机名或ip不能相同")
            return HttpResponse('ok')
        else:
            return HttpResponse('ip或主机名不能为空')
        return render(request, 'assetlist.html')
#         elif Ip:
#             print 'Ip',Ip
#             obj = Asset.objects.get(id=Id)
#             obj.ip = Ip
#             obj.save()
#             return HttpResponse('ok')
    else:
        return HttpResponse('404')


def UserUpdate(request):
    """
    用户信息升级
    :param request: user login
    :return:200
    """
    if not request.session.get('username', 0):
        return redirect('/ad/login/')
    if request.method == 'POST':
        # print request.POST.get('data')
        name = request.POST.get('Name', None)
        email = request.POST.get('Email', None)
        if '@' not in email:
            return HttpResponse('邮箱信息错误')
            exit(0)
        u_id = request.POST.get('Id', None)
        memo = request.POST.get('Memo', None)
        # is_empty = all([Hostname,Ip])
        # print name,email,id,memo
        is_empty = all([name, email, u_id, memo])
        if is_empty:
            print('name', name)
            print('email', email)
            # noinspection PyBroadException
            try:
                obj = UserInfo.objects.get(id=u_id)
                obj.email = email
                obj.name = name
                obj.memo = memo
                obj.save()
            except Exception as e:
                return HttpResponse(0)
                print(e)
            return HttpResponse(200)
        else:
            return HttpResponse(0)
    else:
        return HttpResponse('404')


def AssetList(request):
    """
    资产列表,
    :param request: 用户登录
    @return:
        result: 状态
        asset_list: asset表的objects数据
        assetlistform: assetlistform 表单验证
        host_group: 资产对应的的用户组
    """
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    asset_list = Asset.objects.all()
    result = ''
    assetlistform = AssetListForm()
    host_group = HostGroup.objects.all()
    if request.method == 'POST':
        Hostname = request.POST.get('hostname', None)
        Ip = request.POST.get('ip', None)
        user_group = request.POST.get('user_group', None)
        try:
            groupinstance = UserGroup.objects.get(id=user_group)
        except Exception as e:
            logging.error("user_group", e)
        print(Hostname, Ip, user_group)
        # is_empty = all([Hostname,Ip])
        # print Id,Ip,Hostname
        if Hostname and Ip:
            print('Hostname', Hostname)
            print('ip', Ip)
            try:
                Asset.objects.create(hostname=Hostname, ip=Ip, user_group=groupinstance)
                return render(request, 'assetlist.html',
                              {'data': asset_list, 'form': assetlistform,
                               'host_group': host_group, 'status': result})
            except Exception as e:
                logging.error(e)
                return redirect("/ad/assetlist/")
        else:
            # return HttpResponse('ip或主机名错误')
            return render(request, 'assetlist.html',
                          {'data': asset_list, 'form': assetlistform,
                           'host_group': host_group, 'status': result})
    else:
        return render(request, 'assetlist.html',
                      {'data': asset_list, 'form': assetlistform,
                       'host_group': host_group, 'status': result})


def UserList(request):
    """

    :param request: 用户登录
    @return:
        user_list_name: table 标题
        user_list: 用户数据
    """
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    elif request.session['username'] != "superadmin":
        return redirect('/ad/assetlist/')
    user_list = UserInfo.objects.all()
    user_list_name = ('name', 'email', 'memo', 'typeId', '修改时间', u'创建时间')
    return render(request, 'userlist.html', {'data': user_list, 'list': user_list_name})


def server_monitor(request, name):
    """
    :前置条件: 用户登录
    :param request: 用户请求
    :param name: asset hostname
    :return:
        正确返回: 主机对应最新一条记录的list 格式，方便前台进行Echart处理
        错误返回: 无监控数据
        异常返回: 跳转到/ad/monitor/hostgroup/
    """
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    try:
        server_data = RuleResult.objects.filter(host=name)
        data1 = dict()
        if server_data:
            data1["time"] = []
            data1["cpu"] = []
            data1["memcache"] = []
            data1["load"] = dict()
            data1["inode"] = dict()
            data1["diskpercent"] = dict()
            data1["IOPS"] = dict()
            data1["sentbyte"] = dict()
            data1["recvbyte"] = dict()
            data1["connections"] = dict()
            data1_index = ("load", "inode", "diskpercent",
                           "IOPS", "sentbyte", "recvbyte", "connections")
            # data1['inode']['/'] = []
            # data1['inode']['/boot'] = []
            # data1['inode']['/data'] = []
            for i in range(len(server_data)):
                data1["time"].append(time.mktime(server_data[i].time.timetuple()))
                server_data[i].data = json.loads(server_data[i].data)
                data1["cpu"].append(server_data[i].data["cpupercent"])
                data1["memcache"].append(server_data[i].data["mempercent"])
                for item in data1_index:
                    for k, v in server_data[i].data[item].items():
                        if item == "inode":
                            v = int(v.strip("%"))
                        if type(data1[item].get(k, None)) != list:
                            data1[item][k] = []
                        data1[item][k].append(v)
            data1["host"] = server_data[0].host
            return render(request, "monitor.html", {"data": data1})
        return HttpResponse("无监控数据")
    except Exception as e:
        logging.error("RuleResult", e)
        return redirect("/ad/monitor/hostgroup/")


def server_monitor_host(request):
    """
    从Asset表(主机表)中取出所有主机,
    去RuleResult表(监控结果表)取出每个主机对应的最新数据.
    :param request: 用户请求
    :return:
        正常返回:
            data1:
                host: 主机名; ip: 主机ip;cpu: cpu;mem: 内存;diskpercent: 磁盘百分比
        异常返回: 无监控数据; 跳转到 hostgroup
    """
    # 用户必须登录
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    try:
        server_data = []
        all_host = Asset.objects.all().values("hostname")
        print(all_host)
        for host in all_host:
            one_host = host['hostname']
            one_server_data = RuleResult.objects.filter(host=one_host)
            server_data.append(one_server_data[len(one_server_data)-1])
        print(server_data)
        data1 = []
        if server_data:
            for item in server_data:
                item_data = dict()
                item.data = json.loads(item.data)
                item_data['host'] = item.host
                item_data['ip'] = Asset.objects.filter(hostname=item.host).values("ip")[0]['ip']
                item_data['cpu'] = item.data['cpupercent']
                item_data['mem'] = item.data['mempercent']
                temp_disk_percent = 0
                for k in item.data['diskpercent']:
                    if temp_disk_percent < item.data['diskpercent'][k]:
                        temp_disk_percent = item.data['diskpercent'][k]
                        item_data['disk'] = temp_disk_percent
                        print(temp_disk_percent)
                data1.append(item_data)
            return render(request, "monitor_host.html", {"data": data1})
        return HttpResponse("无监控数据")
    except Exception as e:
        logging.error("RuleResult", e)
        return redirect("/ad/monitor/hostgroup/")


def server_monitor_hostgroup(request):
    """功能未开发"""
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    result = ''
    host_group = HostGroup.objects.all()
    # print(host_group[0].id)
    host_list = dict()
    for i in host_group:
        hosts = Asset.objects.filter(hostgroup=i.id)
        host_list[i.id] = []
        for item in hosts:
            host_list[i.id].append(item.hostname)
    print(host_list)
    return render(request, 'hostgroup.html',
                  {'data': host_group, "host_list": host_list, 'status': result})


def server_monitor_templates(request):
    """功能未开发"""
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    result = ''
    templetes = Templates.objects.all()
    return render(request, 'templetes.html', {'data': templetes,  'status': result})


def server_monitor_triggers(request):
    """功能未开发"""
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    result = ''
    triggers = Triggers.objects.all()
    return render(request, 'triggers.html', {'data': triggers, 'status': result})


def server_monitor_warning(request):
    """
    告警显示, 添加新的告警规则
    :param request: 用户请求
    :return:
    """
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    rule_index = RuleIndex.objects.all()
    result = ''
    rule_index_form = RuleIndexForm()
    triggers = Triggers.objects.all()
    if request.method == 'POST':
        # check_num = triggers_times_choice[int(request.POST["triggers_times"])]
        form = RuleIndexForm(request.POST)
        # form["warning"] = 1 - check_num
        if form.is_valid():
            # data = form.clean()
            # user = data.get('name',None)
            triggers_times_choice = (1, 3, 5, 10, 15, 30)
            post_name = request.POST.get("name", None)
            post_triggers = int(request.POST.get("triggers", None))
            post_time = request.POST.get("time", None)
            post_triggers_times = request.POST.get("triggers_times", None)
            post_triggers_diff = request.POST.get("triggers_diff", None)
            post_triggers_value = request.POST.get("triggers_value", None)
            check_num = triggers_times_choice[int(request.POST["triggers_times"])]
            post_warning = 1 - check_num
            switch = request.POST.get("switch", 1)
            try:
                # form.save()
                RuleIndex.objects.create(name=post_name, triggers_id=post_triggers, time=post_time,
                                         triggers_times=post_triggers_times, triggers_diff=post_triggers_diff,
                                         triggers_value=post_triggers_value, warning=post_warning, switch=switch)
                return redirect('/ad/monitor/warning/')
            except Exception as e:
                logging.error("form.save", e)
        else:
            print("表单无效")
            print(form.clean())
            result = '无效的用户名/密码'
    return render(request, 'warning.html', {'data': rule_index, 'form': triggers,
                                            "form2": rule_index_form, 'status': result})


def server_monitor_warning_update(request):
    """启用/停止 告警规则"""
    if not request.session.get('username', None):
        return redirect('/ad/login/')
    rule_index_id = request.POST.get("id", None)
    rule_index_switch = request.POST.get("switch", None)
    print(rule_index_id, rule_index_switch)
    triggers_times_choice = (1, 3, 5, 10, 15, 30)
    if all([rule_index_id, rule_index_switch]):
        try:
            obj = RuleIndex.objects.get(id=rule_index_id)
            obj.switch = rule_index_switch
            print(type(obj.switch), obj.switch)
            if obj.switch == str(1):
                obj.warning = 1 - triggers_times_choice[obj.triggers_times]
            else:
                obj.warning = -30
            print(obj.warning)
            obj.save()
        except Exception as e:
            print(e)
    return redirect("/ad/monitor/warning/")


def server_monitor_message(request, u_id):
    if request.META.get("REMOTE_ADDR", None) != "192.168.115.21":
        return HttpResponse(status=444)
    try:
        rule_index = RuleIndex.objects.get(id=u_id)
        rule_index_name = RuleIndex.objects.get(id=u_id).name  # this is a number
        triggers_id = RuleIndex.objects.get(id=u_id).triggers_id
        templates_id = Templates.objects.get(triggers=triggers_id).id
        host_group = HostGroup.objects.get(templates=templates_id)
        hosts = Asset.objects.filter(hostgroup=host_group.id)
        triggers_times_choice = (1, 3, 5, 10, 15, 30)
        host_list = []
        temp_warning_status = 0
        rule_index_switch = rule_index.switch
        for item in hosts:
            host_list.append(item.hostname)
            hostname = item.hostname
            rule_result_query_set = RuleResult.objects.filter(host=hostname)
            data = json.loads(rule_result_query_set[len(rule_result_query_set) - 1].data)
            print(type(rule_index_switch), rule_index_switch)
            if not rule_index_switch:
                break
            if len(RuleResult.objects.filter(host=hostname)) == 0:
                continue
            elif time.mktime(rule_result_query_set[len(rule_result_query_set)-1].time.timetuple()) + 120\
                    < time.time():
                continue
            else:
                triggers_times = triggers_times_choice[rule_index.triggers_times]
                triggers_diff = rule_index.triggers_diff_choice[rule_index.triggers_diff][1]
                triggers_value = rule_index.triggers_value
                # print(triggers_times, triggers_diff, triggers_value)
                # print(type(triggers_times), type(triggers_diff), type(triggers_value))
                rule_index_name_choice = ("ping", "cpupercent", "mempercent", "inode",
                                          "diskpercent", "IOPS", "sentbyte",
                                          "connections", "recvbyte", "LISTEN")
                if rule_index_name_choice[rule_index_name] == 'ping':
                    # noinspection PyBroadException
                    try:
                        print("ip", item.ip)
                        tn = telnetlib.Telnet(item.ip, '22', timeout=2)
                        tn.close()
                    except Exception:
                        temp_warning_status += 1
                        if rule_index.warning > 0:
                            send_mail(hostname,
                                      host_group.name,
                                      rule_index_name_choice[rule_index_name],
                                      -1)
                    continue
                print(rule_index_name)
                print(data[rule_index_name_choice[rule_index_name]])
                result_data = data[rule_index_name_choice[rule_index_name]]
                # print(str(result_data) + triggers_diff + str(triggers_value))
                # print(type(result_data))
                if type(result_data) is float or type(result_data) is int:
                    if eval(str(result_data) + triggers_diff + str(triggers_value)):
                        print("参数%s ,当前值为%f" % (rule_index_name_choice[rule_index_name], result_data))
                        temp_warning_status += 1
                        # 邮件报警
                        if rule_index.warning > 0 and\
                                rule_index.warning % triggers_times == 1:
                            send_mail(hostname,
                                      host_group.name,
                                      rule_index_name_choice[rule_index_name],
                                      result_data)
                        print(rule_index.warning, host_group.name)
                        break
                    else:
                        print(rule_index.warning - triggers_times)
                        if rule_index.warning > 0:
                            print("本次告警持续时间为: %d 分钟" %
                                  ((rule_index.warning - 1 + triggers_times) * 5))
                        else:
                            print("%s,参数正常" % rule_index_name_choice[rule_index_name])
                        # reset warning value
                        temp_warning_status += 0
                elif type(result_data) is dict:
                    temp_warning_rule_name = rule_index_name_choice[rule_index_name]
                    for k in result_data:
                        if temp_warning_rule_name == "sentbyte" or temp_warning_rule_name == "recvbyte":
                            temp_last_data = json.loads(rule_result_query_set[len(rule_result_query_set) - 2].data)
                            temp_last_value = temp_last_data[temp_warning_rule_name][k]
                        else:
                            temp_last_value = 0
                        if eval(str(result_data[k]).strip("%") + "-" + str(temp_last_value) +
                                triggers_diff + str(triggers_value)):
                            if type(result_data[k]) != str:
                                # 邮件报警
                                if rule_index.warning > 0 and \
                                        rule_index.warning % triggers_times == 1:
                                    send_mail(hostname,
                                              host_group.name,
                                              rule_index_name_choice[rule_index_name],
                                              result_data)
                                print("参数%s ,当前值为%f" %
                                      (rule_index_name_choice[rule_index_name], result_data[k]))
                                print(result_data[k]-temp_last_value)
                            elif type(result_data[k]) == str:
                                print("参数%s ,当前值为%f" %
                                      (rule_index_name_choice[rule_index_name], int(result_data[k].strip("%"))))
                            temp_warning_status += 1
                            break
                        else:
                            temp_warning_status += 0
                            print("参数正常")
                    else:
                        if rule_index.warning > 0:
                            print("本次告警持续时间为: %d 分钟" %
                                  ((rule_index.warning - 1 + triggers_times) * 5.0))
                elif type(result_data) is list and rule_index_name_choice[rule_index_name] == "LISTEN":
                    addr_and_port = "0.0.0.0:" + str(triggers_value)
                    if addr_and_port not in result_data:
                        temp_warning_status += 1
                        if rule_index.warning > 0 and\
                                rule_index.warning % triggers_times == 1:
                            send_mail(hostname,
                                      host_group.name,
                                      rule_index_name_choice[rule_index_name],
                                      int(-1))
                        print(rule_index.warning, host_group.name)
                        break
                    else:
                        print(rule_index.warning - triggers_times)
                        if rule_index.warning > 0:
                            print("本次告警持续时间为: %d 分钟" %
                                  ((rule_index.warning - 1 + triggers_times) * 5))
                        else:
                            print("%s,参数正常" % rule_index_name_choice[rule_index_name])
                        # reset warning value
                        print("")
                        temp_warning_status += 0
                else:
                    print("其他")
        if temp_warning_status > 0:
            rule_index.warning += 1
            if rule_index_name == 0:
                rule_index.warning = 1
        elif not rule_index_switch:
            rule_index.warning = -30
        else:
            rule_index.warning = 1 - triggers_times
        rule_index.save()
        return render(request, "message.html",
                      {"host_group": host_group, "host_list": host_list, "data": data})
    except Exception as e:
        logging.error("报警规则id错误", e)
        return HttpResponse("ok")


def send_mail(host, host_group, warning_name, warning_value):
    # 设置服务器
    mail_host = "smtp.163.com"
    # 用户名
    mail_user = "17051018558@163.com"
    # 口令
    mail_pass = "j2H1EsQTJ4qRG89z"

    sender = '17051018558@163.com'
    receivers = ['17051018558@163.com']

    message = MIMEText("主机%s 所在主机组 %s 当前发生告警,告警名称为 %s ,当前值为 %f" %
                       (host, host_group, warning_name, warning_value), 'plain', 'utf-8')
    message['From'] = "monitor@huaxixianchang.com"
    message['To'] = "17051018558@163.com"

    subject = "%s 监控告警" % warning_name
    message['Subject'] = Header(subject, 'utf-8')

    try:
        smtpObj = smtplib.SMTP()
        # 25 为 SMTP 端口号
        smtpObj.connect(mail_host, 25)
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(sender, receivers, message.as_string())
        print("邮件发送成功")
    except smtplib.SMTPException as e:
        print("Error: 无法发送邮件", e)

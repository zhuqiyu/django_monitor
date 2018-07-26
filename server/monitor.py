#!/usr/bin/env python
#coding=utf-8
import psutil
import os
import sys
import datetime
import pymysql as db
import json


class serverconfig(object):
    def __init__(self):
        # cpu parameter
        self.system = os.sys.platform
        self.cputimes = psutil.cpu_times()
        self.usertime = psutil.cpu_times().user
        self.systime = psutil.cpu_times().system
        self.idletime = psutil.cpu_times().idle
        self.cputotal = self.idletime + self.systime + self.usertime
        self.cpupercent = round((1-self.idletime/self.cputotal)*100, 2)
        # mem parameter
        self.mem = psutil.virtual_memory()
        self.memtotal = psutil.virtual_memory().total/1024/1024
        self.mempercent = psutil.virtual_memory().percent
        self.memavail = psutil.virtual_memory().available/1024/1024
        if self.system != 'win32':
            self.buffers = psutil.virtual_memory().buffers/1024/1024
            self.cached = psutil.virtual_memory().cached/1024/1024
        # disk parameter
        # 预设空字典
        self.diskpercent = dict()
        self.disksize = dict()
        self.inode = dict()
        self.readcount = dict()
        self.writecount = dict()
        self.IOPS = dict()
        for i in psutil.disk_partitions():
            if i[2] != 'iso9660':
                self.diskpercent[i[0]] = psutil.disk_usage(i[1])[-1]
                self.disksize[i[0]]    = round(psutil.disk_usage(i[1])[0]/1024/1024/1024.0, 3)
                if self.system != 'win32':
                    self.inode[i[0]] = os.popen("""df -ih %s |tail -1|awk '{print $(NF-1)}'"""
                                                % i[0]).read().strip('\n')
        for i in psutil.disk_io_counters(perdisk=True):
            if 'dm' not in i:
                psutil.disk_io_counters.cache_clear()
                self.readcount[i] = psutil.disk_io_counters(perdisk=True)[i][0]
                self.writecount[i] = psutil.disk_io_counters(perdisk=True)[i][1]
        temp_io_num = int(os.popen("""iostat -x -d -k|grep -c d[a-f]""").read().strip('\n'))
        temp_io = os.popen("""iostat -x -d -k 1 2|awk '/d[a-f]/{print $1,$4+$5}'|sed -n '%d,$P'"""
                           % (temp_io_num + 1))
        for item in temp_io:
            item = item.strip('\n').split(" ")
            self.IOPS[item[0]] = item[1]
        # system load
        self.load = dict()
        temp_load = os.popen("""uptime |awk -F ":" '{print $NF}'|tr -d ,""").read().strip("\n").strip().split(" ")
        self.load["load_1m"] = temp_load[0]
        self.load["load_5m"] = temp_load[1]
        self.load["load_15m"] = temp_load[2]
        # network parameter
        self.sentbyte = dict()
        self.recvbyte = dict()
        for i in psutil.net_io_counters(pernic=True):
            self.sentbyte[i] = psutil.net_io_counters(pernic=True)[i][0]
            self.recvbyte[i] = psutil.net_io_counters(pernic=True)[i][1]
        # network connections
        self.connections = dict()
        status_list = ["LISTEN", "ESTABLISHED", "TIME_WAIT",
                       "CLOSE_WAIT", "LAST_ACK", "SYN_SENT"]
        status_temp = []
        net_connections = psutil.net_connections()
        net_total = 0
        for key in net_connections:
            status_temp.append(key.status)
        for status in status_list:
            self.connections[status] = status_temp.count(status)
            net_total += status_temp.count(status)
        self.connections["TOTAL"] = net_total
        # network listen
        self.LISTEN = []
        for k in psutil.net_connections():
            if k.status == "LISTEN" and k.laddr.ip != '::':
                self.LISTEN.append(k.laddr.ip + ':' + str(k.laddr.port))
        self.resposetohtml = {"data": {
            'cpupercent': self.cpupercent,
            'load': self.load,
            'mempercent': self.mempercent,
            'diskpercent': self.diskpercent,
            'inode': self.inode,
            'disksize': self.disksize,
            'readcount': self.readcount,
            'writecount': self.writecount,
            'IOPS': self.IOPS,
            'sentbyte': self.sentbyte,
            'recvbyte': self.recvbyte,
            'connections': self.connections,
            'LISTEN': self.LISTEN,
        },
            "host": "localhost",     # 必须修改
            "ip": "192.168.115.20",  # 必须修改
            "time_stamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            }


if __name__ == "__main__":
    _conn_status = True
    _conn_retries_count = 0
    vcc_pc = serverconfig()
    data = json.dumps(vcc_pc.resposetohtml.get("data", None))
    host = vcc_pc.resposetohtml.get("host", None)
    time_stamp = vcc_pc.resposetohtml.get("time_stamp", None)
    # 主机信息
    hostname = vcc_pc.resposetohtml["host"]
    ip = vcc_pc.resposetohtml["ip"]
    # 1为管理组，默认2为运维组
    user_group = 2
    # 默认1为2核4G主机组
    hostgroup = 1
    # 时间
    create_date = update_date = datetime.datetime.now()
    while _conn_retries_count < 5 and _conn_status:
        try:
            # 必须修改
            conn = db.connect(host="192.168.115.20", user="zhuqiyu", passwd="123", db="ad",
                              charset="utf8", connect_timeout=3)
            _conn_status = False
        except Exception as e:
            _conn_retries_count += 1
    curs = conn.cursor()
    try:
        curs.execute("INSERT INTO ad.ad_ruleresult(data,host,time) VALUES(%s,%s,%s);",
                     (data, host, time_stamp))
        curs.execute("select count(1) from ad.ad_asset where hostname = %s and ip = %s",
                     (hostname, ip))
        num = curs.fetchall()[0][0]
        print(num, type(num))
        if num < 1:
            print("ok")
            curs.execute(
                "INSERT INTO ad_asset(hostname,ip,user_group_id,hostgroup_id,create_date,update_date)\
                 VALUES(%s,%s,%s,%s,%s,%s);",
                (hostname, ip, user_group, hostgroup, create_date, update_date))
        conn.commit()
        print("success", data)
    except Exception as e:
        conn.rollback()
        print("fail", data)
    finally:
        curs.close()
        conn.close()


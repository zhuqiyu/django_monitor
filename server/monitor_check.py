#!/usr/bin/env python
# encoding:utf8
# author: zhuqiyu
import pymysql as db
import requests
from joblib import Parallel, delayed


_conn_status = True
_conn_retries_count = 0
while _conn_retries_count < 5 and _conn_status:
    try:
        conn = db.connect(host="192.168.115.20", user="zhuqiyu", passwd="123", db="ad",\
                          charset="utf8", connect_timeout=3)
        _conn_status = False
    except Exception as e:
        _conn_retries_count += 1
curs = conn.cursor()
try:
    # curs.execute("INSERT INTO ad.ad_ruleresult(data,host,time) VALUES(%s,%s,%s);",(data,host,time_stamp))
    curs.execute("select id from ad_ruleindex")
    # curl_check = curl.Curl()
    # 2进程
    Parallel(n_jobs=2)(delayed(requests.get)
                       ("http://192.168.115.21/ad/monitor/message/%d/" % item[0])
                       for item in curs.fetchall())
    conn.commit()
except Exception as e:
    conn.rollback()
    print("sql 执行失败，已回滚", e)
finally:
    # 游标关闭
    curs.close()
    # 连接关闭
    conn.close()


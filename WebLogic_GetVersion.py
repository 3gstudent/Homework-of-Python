#python3
import re
import sys
import socket
import requests
import time
def getversion_T3(ip, port):
    try:
        print("[*] Try to use T3: " + ip + ":" + str(port))
        for i in range(5):
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((ip, port))
            s.sendall('t3 12.1.2\nAS:2048\nHL:19\n\n'.encode())
            response = s.recv(2048)
            s.close()
            if response.decode('UTF-8') == "HELO":
                print("    T3 is turned on, send data again to get the version")
                continue
            elif "AS" in response.decode('UTF-8') or "HELO" in response.decode('UTF-8'):
                print("    OK")
                versiondata = re.search('[0-9.]{8}', response.decode('UTF-8'))
                version = versiondata.group(0)
                print("[+] T3 Version: " + version)
                break
            else:
                print("[-]")
                print(response.decode('UTF-8'))
                s.close()
                break      
    except Exception as e:
        print(e)
  

def getversion_AdminConsole(ip, port):
    try:  
        url = "http://" + ip + ":" + str(port) + "/console/login/LoginForm.jsp"
        print("\n[*] Try to access Admin Console: " + url)
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36",
        }
        response = requests.get(url, headers=headers, verify=False, timeout=5)
        if response.status_code == 200 and 'Deploying application' in response.text:
            print("    Wait 3 seconds to deploy the application...")
            time.sleep(3)
            response = requests.get(url, headers=headers, verify=False, timeout=8)
        if response.status_code == 200 and 'WebLogic' in response.text:
            print("    Success")
            try:
                versiondata = re.search('[0-9.]{8}', response.text)
                version = versiondata.group(0)    
                print("[+] Admin Console Version: " + version)
            except Exception as e:
                print("    Possibly an earlier version")
                versiondata = re.compile(r"TITLE\>(.*?)\<")
                version = versiondata.findall(response.text)       
                print("[+] " + version[0])

        elif response.status_code == 404 and '10.4.5 404 Not Found' in response.text:
            print("    Weblogic detected, but unable to get version.")
            print("    It is possible to disable the Admin Console, or to modify the configuration of the Admin Console.")
        else:
            print("[-]")
            print(response.status_code)
            print(response.text)
    except Exception as e: 
        print(e)


if __name__ == "__main__":
    if len(sys.argv)!=2: 
        print('Get Version of WebLogic')  
        print('Usage:')
        print('%s <ip>'%(sys.argv[0]))
        print('Eg.')
        print('%s 192.168.1.1'%(sys.argv[0]))       
        sys.exit(0)
    else:
        getversion_T3(sys.argv[1], 7001)
        getversion_AdminConsole(sys.argv[1], 7001)
        
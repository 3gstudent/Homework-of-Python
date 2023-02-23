#python3
import sys
import socket
import ssl
import requests
import sys
import re
import urllib3
urllib3.disable_warnings()

def getversionweb(ip):
    try:  
        url = "https://" + ip + "/js/zimbraMail/share/model/ZmSettings.js"
        print("[*] Try to access: " + url)
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36",
        }
        response = requests.get(url, headers=headers, verify=False, timeout=5)

        if response.status_code == 200 and 'CLIENT_RELEASE' in response.text:
            print("    Success")
            VERSION_name = re.compile(r"CLIENT_VERSION\",					{type:ZmSetting.T_CONFIG, defaultValue:\"(.*?)\"}\);")
            CLIENT_VERSION = VERSION_name.findall(response.text)
            RELEASE_name = re.compile(r"CLIENT_RELEASE\",					{type:ZmSetting.T_CONFIG, defaultValue:\"(.*?)\"}\);")
            CLIENT_RELEASE = RELEASE_name.findall(response.text)
            print("[+] Version: " + CLIENT_VERSION[0])
            print("    Release: " + CLIENT_RELEASE[0])    
        else:
            print("[-]")
            print(response.status_code)
            print(response.text)
    except Exception as e: 
        print(e)

def getversionimap(ip):
    try:
        print("[*] Try to connect: " + ip + ":143")
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, 143))
        s.sendall(''.encode())
        response = s.recv(1024)
        if "OK" in response.decode('UTF-8'):
            print("    OK")
        else:
            print(response.decode('UTF-8'))
            s.close()
            sys.exit(0)
        s.sendall('A001 ID NIL\r\n'.encode())
        response = s.recv(1024)
        if "Zimbra" in response.decode('UTF-8'):
            versiondata=re.compile(r"VERSION\" \"(.*?)\"")
            version = versiondata.findall(response.decode('UTF-8'))[0]
            releasedata=re.compile(r"RELEASE\" \"(.*?)\"")
            release = releasedata.findall(response.decode('UTF-8'))[0]
            print("[+] Version: " + version)
            print("    Release: " + release)
            return release
        else:
            print(response.decode('UTF-8'))
            s.close()
    except Exception as e:
        print(e)
        return "" 

def getversionimapoverssl(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        print("[*] Try to connect: " + hostname[0] + ":993")   
        context = ssl.create_default_context()
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s = context.wrap_socket(s, server_hostname=hostname[0])
        s.settimeout(5)
        s.connect((ip, 993))
        s.sendall(''.encode())
        response = s.recv(1024)
        if "OK" in response.decode('UTF-8'):
            print("    Success")
        else:
            print(response.decode('UTF-8'))
            s.close()
            sys.exit(0)
        s.sendall('A001 ID NIL\r\n'.encode())
        response = s.recv(1024)
        if "Zimbra" in response.decode('UTF-8'):
            versiondata=re.compile(r"VERSION\" \"(.*?)\"")
            version = versiondata.findall(response.decode('UTF-8'))[0]
            releasedata=re.compile(r"RELEASE\" \"(.*?)\"")
            release = releasedata.findall(response.decode('UTF-8'))[0]
            print("[+] Version: " + version)
            print("    Release: " + release)
            return release
        else:
            print(response.decode('UTF-8'))
            s.close()
    except Exception as e:
        print(e)
        return ""

if __name__ == "__main__":
    if len(sys.argv)!=2: 
        print('Get Version of Zimbra')  
        print('Usage:')
        print('%s <ip>'%(sys.argv[0]))
        print('Eg.')
        print('%s 192.168.1.1'%(sys.argv[0]))       
        sys.exit(0)
    else:
        getversionweb(sys.argv[1])
        release = getversionimap(sys.argv[1])
        if len(release) == 0:
            getversionimapoverssl(sys.argv[1])
        
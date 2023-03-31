import requests
import sys
requests.packages.urllib3.disable_warnings()

session = requests.session()

def loginMinIO(url, username, password):
    print("[*] Try to login:" + url)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9"
    }
    target = url + "/api/v1/login"
    d = {"accessKey": username,
        "secretKey": password,
    }
    try:
        res = session.post(target, headers=headers, json=d, verify = False, timeout = 10)
        if res.status_code == 204:
            print('[+] Login Success')
            print("    Cookie:")
            print("    token=" + res.cookies['token'])
            return url
        else:
            print('[-] Login error')
            if "An error occurred when parsing the HTTP request POST at" in res.text and "9000" in url:
                print("    Wrong port,try to use 9001")
                newurl = url.rsplit(':9000')[0] +":9001"
                print("[*] Try to login:" + newurl + "/api/v1/login")
                res = session.post(newurl + "/api/v1/login", headers=headers, json=d, verify = False, timeout = 10)
                if res.status_code == 204:
                    print('[+] Login Success')
                    print("    Cookie:")
                    print("    token=" + res.cookies['token'])
                    return newurl
                else:
                    print('[-] Login error')
                    print("    Wrong port,try to use another port")
                    sys.exit(0)
            else:
                print(res.status_code)
                print(res.text)
                sys.exit(0)        
    except Exception as e:
        print("[!]")
        print(e)
        sys.exit(0)
        
def getversion(url):
    print("[*] Try to get version")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9"
    }
    target = url + "/api/v1/admin/info"
    try:
        res = session.get(target, headers=headers, verify = False, timeout = 10)
        if res.status_code == 200:
            dictt = res.json()["servers"]
            for k in dictt:
                print("   +server:  " + str(k["network"]))
                print("    state:   " + k["state"])
                print("    uptime:  " + str(k["uptime"]))
                print("    version: " + k["version"])
        else:
            print('[-] Login error')
            print(res.status_code)
            print(res.text)
    except Exception as e:
        print("[!]")
        print(e)
        sys.exit(0)


def getinfo(url):
    print("[*] Try to get info")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9"
    }
    target = url + "/api/v1/admin/info"
    try:
        res = session.get(target, headers=headers, verify = False, timeout = 10)
        if res.status_code == 200:
            print("    buckets: " + str(res.json()["buckets"]))
            print("    objects: " + str(res.json()["objects"]))
            dictt = res.json()["servers"]
            for k in dictt:
                print("   +server:  " + str(k["network"]))
                print("    state:   " + k["state"])
                print("    uptime:  " + str(k["uptime"]))
                print("    version: " + k["version"])
                print("    endpoint:" + k["endpoint"])
                print("    drives   :  " + str(k["drives"]))
        else:
            print('[-] Login error')
            print(res.status_code)
            print(res.text)
    except Exception as e:
        print("[!]")
        print(e)
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv)!=5:
        print('')
        print('MinIO_GetVersion')
        print('Usage:')
        print('     %s <host> <username> <password> <mode>'%(sys.argv[0]))
        print('Mode:')
        print('getversion')
        print('getinfo')
        print('Eg.')
        print('     %s http://192.168.1.1:9000 minioadmin minioadmin getinfo'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[1][-1] == "/":
            sys.argv[1] = sys.argv[1][:-1]
        if sys.argv[4] =="getversion":
            url = loginMinIO(sys.argv[1], sys.argv[2], sys.argv[3])
            getversion(url)            
        elif sys.argv[4] =="getinfo":
            url = loginMinIO(sys.argv[1], sys.argv[2], sys.argv[3])
            getinfo(url)
        else:
            print("[!] Wrong parameter")
    

                        



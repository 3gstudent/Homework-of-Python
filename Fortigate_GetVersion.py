#python3
import requests
import sys
import urllib3
import re
urllib3.disable_warnings()
import gzip

headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
}

versionarray = [
["97a9a8eadad35e7c450cd9aae0848ee7", "7.2.3"],
["df91004ba8e5e244e7af97a888494774", "7.2.2"],
["4885e9396f0d5f343a31e82c0bc37c91", "7.2.1"],
["b911aeb68426644df64811a094b12f98", "7.0.6"],
]

def VersionScan(hash):
    for value in versionarray:
        if (hash ==  value[0]):
            print("    Version: " + value[1])
 
def GetVersion(url):
    try:  
        response = requests.get(url, headers=headers, verify=False, timeout=10, )
        if response.status_code==200 and "top.location=" in response.text:
            print("[*] Try to redirect")
            redirect_name = re.compile(r"top.location=\"(.*?)\"")
            redirect = redirect_name.findall(response.text)
            print("    URL: " + redirect[0])
        
            url1 = url + redirect[0]
            response = requests.get(url1, headers=headers, verify=False, timeout=10)          
            if re.search("[0-9a-f]{32}", response.text):
                hash = re.search('[0-9a-f]{32}', response.text)
                print("[+] " + url)
                print("    Mode: SSL Vpn Client")
                print("    Hash: " + hash.group(0))
                VersionScan(hash.group(0))        
            else:
                print("[-] " + url)
                print("Maybe an old version of Fortigate")
                print(response.status_code)
                print(response.content)

        else:
            if re.search("[0-9a-f]{32}", response.text) is None:
                result = gzip.decompress(response.content)
                hash = re.search('[0-9a-f]{32}', result.decode('utf8'))
            else:
                hash = re.search('[0-9a-f]{32}', response.text)
            print("[+] " + url)
            print("    Mode: Mode: Admin Management")
            print("    Hash: " + hash.group(0))
            VersionScan(hash.group(0))        

    except:
        print("[-] " + url)
        print("Maybe not Fortigate")
        print(sys.exc_info())


if __name__ == "__main__":
    if len(sys.argv)!=2:
        print('Fortigate_GetVersion')        
        print('Usage:')
        print('%s <url>'%(sys.argv[0]))
        print('Eg.')
        print('%s https://192.168.1.1:4443/'%(sys.argv[0]))      
        sys.exit(0)
    else:
        if sys.argv[1][-1] == "/":
            sys.argv[1] = sys.argv[1][:-1]
        GetVersion(sys.argv[1])


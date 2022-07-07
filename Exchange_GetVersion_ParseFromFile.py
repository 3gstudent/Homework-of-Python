#!python3
import requests
import sys
import re
import urllib3
urllib3.disable_warnings()
from bs4 import BeautifulSoup

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
}

def FetchInformation():
    url = "https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019"
    response = requests.get(url, verify=False, headers=headers)
    soup = BeautifulSoup(response.text, features="html.parser")
    print("[*] Try to access " + url)
    print("[+] Article date: " + soup.find('time').text)
    return soup

def ParseVersion(version, soup):
    for tag in soup.find_all('tr'):
        if version in tag.text:
            print("[+] Exchange Information")
            for versiondata in tag.stripped_strings:
                if (len(versiondata)==5):
                    continue
                print("    " + versiondata)

def GetVersion(host):
    try:
        print("[*] Trying to access EWS")
        url1 = "https://" + host + "/ews"
        req = requests.get(url1, headers = headers, verify=False)
        if "X-FEServer" not in req.headers:
            print("[!] Exchange 2010 or older")
            print("[*] Trying to access OWA")
            url2 = "https://" + host + "/owa"
            req = requests.get(url2, headers = headers, verify=False)
            pattern_version = re.compile(r"/owa/(.*?)/themes/resources/favicon.ico")
            version = pattern_version.findall(req.text)[0]
            if "auth" in version:
                version = version.split('/')[1]            
            print("[+] Version:" + version)
            return version
        else:
            print("[+] X-FEServer:" + req.headers["X-FEServer"])

        if "X-OWA-Version" in req.headers:
            version = req.headers["X-OWA-Version"]
            print("[+] X-OWA-Version:" + version)
            return version

        else:
            print("[!] No X-OWA-Version")
            print("[*] Trying to access OWA")
            url2 = "https://" + host + "/owa"
            req = requests.get(url2, headers = headers, verify=False)
            pattern_version = re.compile(r"/owa/auth/(.*?)/themes/resources/favicon.ico")
            version = pattern_version.findall(req.text)[0]
            print("[+] Version:" + version)
            return version
         
    except Exception as e:
        print("[!] "+str(e))
        sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv)!=2:    
        print('Exchange_GetVersion_ParseFromWebsite.py')       
        print('Use to get the version of Exchange and parse the version from https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019')
        print('Usage:')
        print('%s <path>'%(sys.argv[0]))
        print('Eg.')
        print('%s 192.168.1.1'%(sys.argv[0]))      
        sys.exit(0)
    else:
        version = GetVersion(sys.argv[1])
        soup = FetchInformation()
        ParseVersion(version, soup)


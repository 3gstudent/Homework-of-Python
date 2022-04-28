import requests
import sys
import os
import re
requests.packages.urllib3.disable_warnings()

def escape(_str):
    _str = _str.replace("&amp;", "&")
    _str = _str.replace("&lt;", "<")
    _str = _str.replace("&gt;", ">")
    _str = _str.replace("&quot;", "\"")
    return _str

def get_version(url):

    def getValue(sResponse, sTag = "vendor"):
        try:
            return sResponse.split("<" + sTag + ">")[1].split("</" + sTag + ">")[0]
        except:
            pass
        return ""

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    url1 = "https://" + url + "/suite-api/docs/wadl.xml"    
    res = requests.get(url1, verify = False)
    if res.status_code == 200:
        pattern_data = re.compile(r"getCurrentVersionOfServer(.*?)</ns2:doc>", re.MULTILINE|re.DOTALL)
        versiondata = pattern_data.findall(escape(res.text))
        releaseName = getValue(versiondata[0], "ops:releaseName")
        major = getValue(versiondata[0], "ops:major")
        minor = getValue(versiondata[0], "ops:minor")
        minorMinor = getValue(versiondata[0], "ops:minorMinor")
        releasedDate = getValue(versiondata[0], "ops:releasedDate")
        print("[+] Result: ")
        print("    releaseName:  " + releaseName)      
        print("    major:        " + major)
        print("    minorMinor:   " + minorMinor)
        print("    releasedDate: " + releasedDate)

    else:
        print("[!] Maybe not vRealize Operations Manager")
        print(res.status_code)
        print(res.text)


if __name__ == "__main__":
    if len(sys.argv)!=2:
        print('vRealizeOperationsManager_GetVersion')
        print('Use to get the version of vRealize Operations Manager')
        print('Usage:')
        print('     %s <host>'%(sys.argv[0]))
        print('Eg.')
        print('     %s 192.168.1.1'%(sys.argv[0]))      
        sys.exit(0)
    else:
        get_version(sys.argv[1])
    

                        
  

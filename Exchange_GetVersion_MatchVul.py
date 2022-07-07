#!python3
import requests
import sys
import re
import urllib3
urllib3.disable_warnings()

versionarray = [
["Exchange Server 2019 CU12 May22SU", "05/10/2022", "15.2.1118.9"],
["Exchange Server 2019 CU12 (2022H1)", "04/20/2022", "15.2.1118.7"],
["Exchange Server 2019 CU11 May22SU", "05/10/2022", "15.2.986.26"],
["Exchange Server 2019 CU11 Mar22SU", "03/08/2022", "15.2.986.22"],
["Exchange Server 2019 CU11 Jan22SU", "01/11/2022", "15.2.986.15"],
["Exchange Server 2019 CU11 Nov21SU", "11/09/2021", "15.2.986.14"],
["Exchange Server 2019 CU11 Oct21SU", "10/12/2021", "15.2.986.9"],
["Exchange Server 2019 CU11", "09/28/2021", "15.2.986.5"],
["Exchange Server 2019 CU10 Mar22SU", "03/08/2022", "15.2.922.27"],
["Exchange Server 2019 CU10 Jan22SU", "01/11/2022", "15.2.922.20"],
["Exchange Server 2019 CU10 Nov21SU", "11/09/2021", "15.2.922.19"],
["Exchange Server 2019 CU10 Oct21SU", "10/12/2021", "15.2.922.14"],
["Exchange Server 2019 CU10 Jul21SU", "07/13/2021", "15.2.922.13"],
["Exchange Server 2019 CU10", "07/29/2021", "15.2.922.7"],
["Exchange Server 2019 CU9 Jul21SU", "07/13/2021", "15.2.858.15"],
["Exchange Server 2019 CU9 May21SU", "05/11/2021", "15.2.858.12"],
["Exchange Server 2019 CU9 Apr21SU", "04/13/2021", "15.2.858.10"],
["Exchange Server 2019 CU9", "03/16/2021", "15.2.858.5"],
["Exchange Server 2019 CU8 May21SU", "05/11/2021", "15.2.792.15"],
["Exchange Server 2019 CU8 Apr21SU", "04/13/2021", "15.2.792.13"],
["Exchange Server 2019 CU8 Mar21SU", "03/02/2021", "15.2.792.10"],
["Exchange Server 2019 CU8", "12/15/2020", "15.2.792.3"],
["Exchange Server 2019 CU7 Mar21SU", "03/02/2021", "15.2.721.13"],
["Exchange Server 2019 CU7", "09/15/2020", "15.2.721.2"],
["Exchange Server 2019 CU6 Mar21SU", "03/02/2021", "15.2.659.12"],
["Exchange Server 2019 CU6", "06/16/2020", "15.2.659.4"],
["Exchange Server 2019 CU5 Mar21SU", "03/02/2021", "15.2.595.8"],
["Exchange Server 2019 CU5", "03/17/2020", "15.2.595.3"],
["Exchange Server 2019 CU4 Mar21SU", "03/02/2021", "15.2.529.13"],
["Exchange Server 2019 CU4", "12/17/2019", "15.2.529.5"],
["Exchange Server 2019 CU3 Mar21SU", "03/02/2021", "15.2.464.15"],
["Exchange Server 2019 CU3", "09/17/2019", "15.2.464.5"],
["Exchange Server 2019 CU2 Mar21SU", "03/02/2021", "15.2.397.11"],
["Exchange Server 2019 CU2", "06/18/2019", "15.2.397.3"],
["Exchange Server 2019 CU1 Mar21SU", "03/02/2021", "15.2.330.11"],
["Exchange Server 2019 CU1", "02/12/2019", "15.2.330.5"],
["Exchange Server 2019 RTM Mar21SU", "03/02/2021", "15.2.221.18"],
["Exchange Server 2019 RTM", "10/22/2018", "15.2.221.12"],
["Exchange Server 2019 Preview", "07/24/2018", "15.2.196.0"],
["Exchange Server 2016 CU23 May22SU", "05/10/2022", "15.1.2507.9"],
["Exchange Server 2016 CU23 (2022H1)", "04/20/2022", "15.1.2507.6"],
["Exchange Server 2016 CU22 May22SU", "05/10/2022", "15.1.2375.28"],
["Exchange Server 2016 CU22 Mar22SU", "03/08/2022", "15.1.2375.24"],
["Exchange Server 2016 CU22 Jan22SU", "01/11/2022", "15.1.2375.18"],
["Exchange Server 2016 CU22 Nov21SU", "11/09/2021", "15.1.2375.17"],
["Exchange Server 2016 CU22 Oct21SU", "10/12/2021", "15.1.2375.12"],
["Exchange Server 2016 CU22", "09/28/2021", "15.1.2375.7"],
["Exchange Server 2016 CU21 Mar22SU", "03/08/2022", "15.1.2308.27"],
["Exchange Server 2016 CU21 Jan22SU", "01/11/2022", "15.1.2308.21"],
["Exchange Server 2016 CU21 Nov21SU", "11/09/2021", "15.1.2308.20"],
["Exchange Server 2016 CU21 Oct21SU", "10/12/2021", "15.1.2308.15"],
["Exchange Server 2016 CU21 Jul21SU", "07/13/2021", "15.1.2308.14"],
["Exchange Server 2016 CU21", "07/29/2021", "15.1.2308.8"],
["Exchange Server 2016 CU20 Jul21SU", "07/13/2021", "15.1.2242.12"],
["Exchange Server 2016 CU20 May21SU", "05/11/2021", "15.1.2242.10"],
["Exchange Server 2016 CU20 Apr21SU", "04/13/2021", "15.1.2242.8"],
["Exchange Server 2016 CU20", "03/16/2021", "15.1.2242.4"],
["Exchange Server 2016 CU19 May21SU", "05/11/2021", "15.1.2176.14"],
["Exchange Server 2016 CU19 Apr21SU", "04/13/2021", "15.1.2176.12"],
["Exchange Server 2016 CU19 Mar21SU", "03/02/2021", "15.1.2176.9"],
["Exchange Server 2016 CU19", "12/15/2020", "15.1.2176.2"],
["Exchange Server 2016 CU18 Mar21SU", "03/02/2021", "15.1.2106.13"],
["Exchange Server 2016 CU18", "09/15/2020", "15.1.2106.2"],
["Exchange Server 2016 CU17 Mar21SU", "03/02/2021", "15.1.2044.13"],
["Exchange Server 2016 CU17", "06/16/2020", "15.1.2044.4"],
["Exchange Server 2016 CU16 Mar21SU", "03/02/2021", "15.1.1979.8"],
["Exchange Server 2016 CU16", "03/17/2020", "15.1.1979.3"],
["Exchange Server 2016 CU15 Mar21SU", "03/02/2021", "15.1.1913.12"],
["Exchange Server 2016 CU15", "12/17/2019", "15.1.1913.5"],
["Exchange Server 2016 CU14 Mar21SU", "03/02/2021", "15.1.1847.12"],
["Exchange Server 2016 CU14", "09/17/2019", "15.1.1847.3"],
["Exchange Server 2016 CU13 Mar21SU", "03/02/2021", "15.1.1779.8"],
["Exchange Server 2016 CU13", "06/18/2019", "15.1.1779.2"],
["Exchange Server 2016 CU12 Mar21SU", "03/02/2021", "15.1.1713.10"],
["Exchange Server 2016 CU12", "02/12/2019", "15.1.1713.5"],
["Exchange Server 2016 CU11 Mar21SU", "03/02/2021", "15.1.1591.18"],
["Exchange Server 2016 CU11", "10/16/2018", "15.1.1591.10"],
["Exchange Server 2016 CU10 Mar21SU", "03/02/2021", "15.1.1531.12"],
["Exchange Server 2016 CU10", "06/19/2018", "15.1.1531.3"],
["Exchange Server 2016 CU9 Mar21SU", "03/02/2021", "15.1.1466.16"],
["Exchange Server 2016 CU9", "03/20/2018", "15.1.1466.3"],
["Exchange Server 2016 CU8 Mar21SU", "03/02/2021", "15.1.1415.10"],
["Exchange Server 2016 CU8", "12/19/2017", "15.1.1415.2"],
["Exchange Server 2016 CU7", "09/19/2017", "15.1.1261.35"],
["Exchange Server 2016 CU6", "06/27/2017", "15.1.1034.26"],
["Exchange Server 2016 CU5", "03/21/2017", "15.1.845.34"],
["Exchange Server 2016 CU4", "12/13/2016", "15.1.669.32"],
["Exchange Server 2016 CU3", "09/20/2016", "15.1.544.27"],
["Exchange Server 2016 CU2", "06/21/2016", "15.1.466.34"],
["Exchange Server 2016 CU1", "03/15/2016", "15.1.396.30"],
["Exchange Server 2016 RTM", "10/01/2015", "15.1.225.42"],
["Exchange Server 2016 Preview", "07/22/2015", "15.1.225.16"],
["Exchange Server 2013 CU23 May22SU", "05/10/2022", "15.0.1497.36"],
["Exchange Server 2013 CU23 Mar22SU", "03/08/2022", "15.0.1497.33"],
["Exchange Server 2013 CU23 Jan22SU", "01/11/2022", "15.0.1497.28"],
["Exchange Server 2013 CU23 Nov21SU", "11/09/2021", "15.0.1497.26"],
["Exchange Server 2013 CU23 Oct21SU", "10/12/2021", "15.0.1497.24"],
["Exchange Server 2013 CU23 Jul21SU", "07/13/2021", "15.0.1497.23"],
["Exchange Server 2013 CU23 May21SU", "05/11/2021", "15.0.1497.18"],
["Exchange Server 2013 CU23 Apr21SU", "04/13/2021", "15.0.1497.15"],
["Exchange Server 2013 CU23 Mar21SU", "03/02/2021", "15.0.1497.12"],
["Exchange Server 2013 CU23", "06/18/2019", "15.0.1497.2"],
["Exchange Server 2013 CU22 Mar21SU", "03/02/2021", "15.0.1473.6"],
["Exchange Server 2013 CU22", "02/12/2019", "15.0.1473.3"],
["Exchange Server 2013 CU21 Mar21SU", "03/02/2021", "15.0.1395.12"],
["Exchange Server 2013 CU21", "06/19/2018", "15.0.1395.4"],
["Exchange Server 2013 CU20", "03/20/2018", "15.0.1367.3"],
["Exchange Server 2013 CU19", "12/19/2017", "15.0.1365.1"],
["Exchange Server 2013 CU18", "09/19/2017", "15.0.1347.2"],
["Exchange Server 2013 CU17", "06/27/2017", "15.0.1320.4"],
["Exchange Server 2013 CU16", "03/21/2017", "15.0.1293.2"],
["Exchange Server 2013 CU15", "12/13/2016", "15.0.1263.5"],
["Exchange Server 2013 CU14", "09/20/2016", "15.0.1236.3"],
["Exchange Server 2013 CU13", "06/21/2016", "15.0.1210.3"],
["Exchange Server 2013 CU12", "03/15/2016", "15.0.1178.4"],
["Exchange Server 2013 CU11", "12/15/2015", "15.0.1156.6"],
["Exchange Server 2013 CU10", "09/15/2015", "15.0.1130.7"],
["Exchange Server 2013 CU9", "06/17/2015", "15.0.1104.5"],
["Exchange Server 2013 CU8", "03/17/2015", "15.0.1076.9"],
["Exchange Server 2013 CU7", "12/09/2014", "15.0.1044.25"],
["Exchange Server 2013 CU6", "08/26/2014", "15.0.995.29"],
["Exchange Server 2013 CU5", "05/27/2014", "15.0.913.22"],
["Exchange Server 2013 SP1 Mar21SU", "03/02/2021", "15.0.847.64"],
["Exchange Server 2013 SP1", "02/25/2014", "15.0.847.32"],
["Exchange Server 2013 CU3", "11/25/2013", "15.0.775.38"],
["Exchange Server 2013 CU2", "07/09/2013", "15.0.712.24"],
["Exchange Server 2013 CU1", "04/02/2013", "15.0.620.29"],
["Exchange Server 2013 RTM", "12/03/2012", "15.0.516.32"]
]

vularray = [
["CVE-2020-0688", "02/11/2020"],
["CVE-2021-26855+CVE-2021-27065", "03/02/2021"],
["CVE-2021-28482", "04/13/2021"],
["CVE-2021-34473+CVE-2021-34523+CVE-2021-31207", "04/13/2021"],
["CVE-2021-31195+CVE-2021-31196", "05/11/2020"],
["CVE-2021-31206", "07/13/2021"],
["CVE-2021-42321", "11/09/2021"],
["CVE-2022-23277", "03/08/2022"],
]

def vulscan(date):
    for value in vularray:
        if (date.split('/')[2] < value[1].split('/')[2]):
            print("[+] " + value[0] + ", " + value[1])
        else:
            if (date.split('/')[2] == value[1].split('/')[2]) & (date.split('/')[0] < value[1].split('/')[0]):
                print("[+] " + value[0] + ", " + value[1])
            else:
                if (date.split('/')[2] == value[1].split('/')[2]) & (date.split('/')[0] == value[1].split('/')[0]) & (date.split('/')[1] < value[1].split('/')[1]):
                    print("[+] " + value[0] + ", " + value[1])

def matchversion(version):
    for value in versionarray:
        if version in value:
            print("[+] Product: " + value[0])
            print("    Date: " + value[1])
            vulscan(value[1])

def guessversion(version):
    for value in versionarray:
        if version in value[2][:value[2].rfind(".")]:
            print("[+] Guessed Version: " + value[2])
            print("    Product: " + value[0])
            print("    Date: " + value[1])          
            vulscan(value[1])

def GetVersion_MatchVul(host):
    try:
        print("[*] Trying to access EWS")
        headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
        } 
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
                guessversion(version)
            print("[+] Version:" + version)
            sys.exit(0)
        else:
            print("[+] X-FEServer:" + req.headers["X-FEServer"])

        if "X-OWA-Version" in req.headers:
            version = req.headers["X-OWA-Version"]
            print("[+] X-OWA-Version:" + version)
            print("[*] Trying to get the full version and match the vul")
            matchversion(version)

        else:
            print("[!] No X-OWA-Version")
            print("[*] Trying to access OWA")
            url2 = "https://" + host + "/owa"
            req = requests.get(url2, headers = headers, verify=False)
            pattern_version = re.compile(r"/owa/auth/(.*?)/themes/resources/favicon.ico")
            version = pattern_version.findall(req.text)[0]
            print("[+] Version:" + version)
            print("[*] Trying to guess the full version and match the vul")
            guessversion(version)
         
    except Exception as e:
        print("[!] "+str(e))
        sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv)!=2:    
        print('Exchange_GetVersion_MatchVul.py')       
        print('Use to get the version of Exchange and match the existing vulnerabilities')
        print('Usage:')
        print('%s <path>'%(sys.argv[0]))
        print('Eg.')
        print('%s 192.168.1.1'%(sys.argv[0]))      
        sys.exit(0)
    else:
        print("[*] Exchange Server build numbers and release dates: 06/29/2022")
        print("    https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019")
        GetVersion_MatchVul(sys.argv[1])


#python3
import requests
import base64
import sys
import json
import os
import urllib3
urllib3.disable_warnings()
import urllib.parse

def Check(api_host, username, password):
    url = api_host + "/Orion/Login.aspx?autologin=no"

    body = {
            "__EVENTTARGET": "ctl00$BodyContent$LoginButton",
            "ctl00$BodyContent$Username": username,
            "ctl00$BodyContent$Password": password
            }
    
    postData = urllib.parse.urlencode(body).encode("utf-8")
            
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/x-www-form-urlencoded",    
    }
          
    r = requests.post(url, headers = headers, data=postData, verify = False)
    if r.status_code ==200 and "__AntiXsrfToken" in r.headers['set-cookie']:
        print("[+] Valid:%s  %s"%(username, password))
        r.close()
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        r.close()
        exit(0) 

    
def GetAccounts(api_host, username, password):
    session = requests.session()
    url = api_host + "/Orion/Login.aspx?autologin=no"

    body = {
            "__EVENTTARGET": "ctl00$BodyContent$LoginButton",
            "ctl00$BodyContent$Username": username,
            "ctl00$BodyContent$Password": password
            }
    
    postData = urllib.parse.urlencode(body).encode("utf-8")
            
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/x-www-form-urlencoded",    
    }
          
    r = session.post(url, headers = headers, data=postData, verify = False)
    if r.status_code !=200 or "__AntiXsrfToken" not in r.headers['set-cookie']:
        print("[!]")
        print(r.status_code)
        print(r.text)
        r.close()
        exit(0)

    print("[+] Valid:%s  %s"%(username, password))

    r = session.post(url, headers = headers, data=postData, verify = False, allow_redirects=False)
    index = r.headers['Set-Cookie'].index('XSRF-TOKEN')
    xsrfToken = r.headers["Set-Cookie"][index+11:index+55]
    print("[+] XSRF-TOKEN: " + xsrfToken)
    
    url1 = api_host + "/Orion/Services/AccountManagement.asmx/GetAccounts?sort=Accounts.AccountID&dir=ASC"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/json",
        "X-XSRF-TOKEN":xsrfToken
    }

    data =  {"accountId":""}    
    r = session.post(url1, headers = headers, data=json.dumps(data), verify = False)

    dic = r.json()['d']['DataTable']['Rows']
    for i in dic:  
        print(" -  Name:" + str(i[0]))
        print("    Type:" + str(i[1]))
        print("    Enabled:" + str(i[2]))
        print("    Expires:" + str(i[3]))
        print("    LastLogin:" + str(i[3]))

      
def QueryData(api_host, username, password, query, **params):
    session = requests.session()
    url = api_host + "/Orion/Login.aspx?autologin=no"

    body = {
            "__EVENTTARGET": "ctl00$BodyContent$LoginButton",
            "ctl00$BodyContent$Username": username,
            "ctl00$BodyContent$Password": password
            }
    
    postData = urllib.parse.urlencode(body).encode("utf-8")
            
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/x-www-form-urlencoded",    
    }
          
    r = session.post(url, headers = headers, data=postData, verify = False)
    if r.status_code !=200 or "__AntiXsrfToken" not in r.headers['set-cookie']:
        print("[!]")
        print(r.status_code)
        print(r.text)
        r.close()
        exit(0)

    print("[+] Valid:%s  %s"%(username, password))

    r = session.post(url, headers = headers, data=postData, verify = False, allow_redirects=False)
    index = r.headers['Set-Cookie'].index('XSRF-TOKEN')
    xsrfToken = r.headers["Set-Cookie"][index+11:index+55]
    print("[+] XSRF-TOKEN: " + xsrfToken)
    
    url1 = api_host + "/api2/swis/query?lang=en-us&swAlertOnError=false"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/json",
        "X-XSRF-TOKEN":xsrfToken
    }

    data =  {
                "query": query,
                "parameters":params   
            }
    
    r = session.post(url1, headers = headers, data=json.dumps(data), verify = False)
    if "Result" in r.json():
        print("[+] Result: ")
        dic = r.json()['Result']
        for i in dic:       
            print(i)
    else:
        print("[!]")
        print(r.json())


if __name__ == "__main__":

    if len(sys.argv)!=5:
        print("SolarWindsOrion_Manage")
        print("Use to manage the SolarWinds Orion platform")   
        print("Usage:")
        print("%s <IP:PORT> <username> <password> <mode>"%(sys.argv[0]))
        print("mode:")
        print("- Check")
        print("- GetAccounts")
        print("- GetAlertActive")
        print("- GetAlertHistory")
        print("- GetCredential")
        print("- GetNodes")
        print("- GetOrionServers")
        print("- query")
 
        print("Eg.")
        print("%s http://192.168.1.1:8787 admin Password123 GetAccounts"%(sys.argv[0]))      
        sys.exit(0)
    else:
        if sys.argv[4] == "Check":
            Check(sys.argv[1], sys.argv[2], sys.argv[3])
            
        elif sys.argv[4] == "GetAccounts":
            GetAccounts(sys.argv[1], sys.argv[2], sys.argv[3])

        elif sys.argv[4] == "GetAlertActive":  
            print("[*] GetAlertActive")
            query = "SELECT TOP 1000 TriggeredDateTime,TriggeredMessage FROM Orion.AlertActive"
            params = {}
            QueryData(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)

        elif sys.argv[4] == "GetAlertHistory":  
            print("[*] GetAlertHistory")
            query = "SELECT TOP 1000 Message,TimeStamp FROM Orion.AlertHistory"
            params = {}
            QueryData(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)            

        elif sys.argv[4] == "GetCredential":  
            print("[*] GetCredential")
            query = "SELECT TOP 1000 ID,Name,Description,CredentialType,CredentialOwner FROM Orion.Credential"
            params = {}
            QueryData(sys.argv[1], sys.argv[2], sys.argv[3], query, **params) 

        elif sys.argv[4] == "GetNodes":  
            print("[*] GetNodes")
            query = "SELECT TOP 1000 IP_Address,Caption,DNS,SysName,Vendor,Description,Location,IOSVersion,StatusDescription,MachineType,IsServer,SNMPVersion,EntityType FROM Orion.Nodes"
            params = {}
            QueryData(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)

        elif sys.argv[4] == "GetOrionServers":  
            print("[*] GetOrionServers")
            query = "SELECT TOP 1000 ServerType,HostName,SWAKeepAlive,SWAVersion,Details FROM Orion.OrionServers"
            params = {}
            QueryData(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)
     
        elif sys.argv[4] == "query":
            print("[*] query")
            print("[*] parameter:")
            print("    - query ")
            query = input("input the query: (eg. SELECT AccountID FROM Orion.Accounts )")
            params = {}
            QueryData(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)
            
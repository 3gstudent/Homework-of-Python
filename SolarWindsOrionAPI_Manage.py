#python3
import requests
import base64
import sys
import json
import os
import warnings
warnings.filterwarnings("ignore")

def SWIS_query(api_host, username, password, query, **params):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + ":17778/SolarWinds/InformationService/v3/Json/Query"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential,
        "Content-Type": "application/json"

    }

    data =  {
                "query": query,
                "parameters":params   
            }
            
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==200: 
        print("[+] query success")
        for i in r.json()["results"]:
            print(i)
             
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        exit(0) 
        

def SWIS_invoke(api_host, username, password, entity, verb, *args):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + ":17778/SolarWinds/InformationService/v3/Json/Invoke/" + entity + "/" + verb
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential,
        "Content-Type": "application/json"

    }
           
    r = requests.post(url, headers = headers, data=json.dumps(args), verify = False)
    if r.status_code ==200:
        print("[+] invoke success")
        print(r.text)        
             
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        exit(0) 


def SWIS_create(api_host, username, password, entity, **properties):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + ":17778/SolarWinds/InformationService/v3/Json/Create/" + entity
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential,
        "Content-Type": "application/json"

    }
           
    r = requests.post(url, headers = headers, data=json.dumps(properties), verify = False)
    if r.status_code ==200:
        print("[+] create success")
        print(r.text)        
             
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        exit(0) 


def SWIS_read(api_host, username, password, uri):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + ":17778/SolarWinds/InformationService/v3/Json/" + uri
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential,
        "Content-Type": "application/json"

    }
           
    r = requests.get(url, headers = headers, verify = False)
    if r.status_code ==200:
        print("[+] read success")
        print(r.text)        
             
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        exit(0) 


def SWIS_update(api_host, username, password, uri, **properties):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + ":17778/SolarWinds/InformationService/v3/Json/" + uri
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential,
        "Content-Type": "application/json"

    }
           
    r = requests.post(url, headers = headers, data=json.dumps(properties), verify = False)
    if r.status_code ==200:
        print("[+] update success")
        print(r.text)        
             
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        exit(0) 
    

def SWIS_bulkupdate(api_host, username, password, uris, **properties):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + ":17778/SolarWinds/InformationService/v3/Json/BulkUpdate"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential,
        "Content-Type": "application/json"

    }

    data =  {'uris': uris, 'properties': properties}
     
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==200: 
        print("[+] bulkupdate success")
        print(r.text)
             
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        exit(0) 


def SWIS_delete(api_host, username, password, uri):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + ":17778/SolarWinds/InformationService/v3/Json/" + uri
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential,
        "Content-Type": "application/json"

    }
           
    r = requests.delete(url, headers = headers, verify = False)
    if r.status_code ==200:
        print("[+] delete success")
        print(r.text)        
             
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        exit(0) 


def SWIS_bulkdelete(api_host, username, password, uris):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + ":17778/SolarWinds/InformationService/v3/Json/BulkDelete"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential,
        "Content-Type": "application/json"

    }

    data =  {'uris': uris}
           
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==200:
        print("[+] bulkdelete success")
        print(r.text)        
             
    else:         
        print("[!]")
        print(r.status_code)
        print(r.text)
        exit(0) 


if __name__ == "__main__":

    if len(sys.argv)!=5:
        print("SolarWindsOrionAPI_Manage")
        print("Use SolarWinds Orion API to manage the Orion platform")   
        print("Usage:")
        print("%s <IP> <username> <password> <mode>"%(sys.argv[0]))
        print("mode:")
        print("- GetAccounts")
        print("- GetAlertActive")
        print("- GetAlertHistory")
        print("- GetCredential")
        print("- GetNodes")
        print("- GetOrionServers")
        print("- query")        
        print("- invoke")
        print("- create")
        print("- read")
        print("- update")
        print("- bulkupdate")
        print("- delete")        
        print("- bulkdelete")        
 
        print("Eg.")
        print("%s 192.168.1.1 admin Password123 GetAccounts"%(sys.argv[0]))      
        sys.exit(0)
    else:

        if sys.argv[4] == "GetAccounts":  
            print("[*] GetAccounts")
            query = "SELECT TOP 1000 AccountID,MenuName,LastLogin FROM Orion.Accounts"
            params = {}
            SWIS_query(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)

        elif sys.argv[4] == "GetAlertActive":  
            print("[*] GetAlertActive")
            query = "SELECT TOP 1000 TriggeredDateTime,TriggeredMessage FROM Orion.AlertActive"
            params = {}
            SWIS_query(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)

        elif sys.argv[4] == "GetAlertHistory":  
            print("[*] GetAlertHistory")
            query = "SELECT TOP 1000 Message,TimeStamp FROM Orion.AlertHistory"
            params = {}
            SWIS_query(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)            

        elif sys.argv[4] == "GetCredential":  
            print("[*] GetCredential")
            query = "SELECT TOP 1000 ID,Name,Description,CredentialType,CredentialOwner FROM Orion.Credential"
            params = {}
            SWIS_query(sys.argv[1], sys.argv[2], sys.argv[3], query, **params) 

        elif sys.argv[4] == "GetNodes":  
            print("[*] GetNodes")
            query = "SELECT TOP 1000 IP_Address,Caption,DNS,SysName,Vendor,Description,Location,IOSVersion,StatusDescription,MachineType,IsServer,SNMPVersion,EntityType FROM Orion.Nodes"
            params = {}
            SWIS_query(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)

        elif sys.argv[4] == "GetOrionServers":  
            print("[*] GetOrionServers")
            query = "SELECT TOP 1000 ServerType,HostName,SWAKeepAlive,SWAVersion,Details FROM Orion.OrionServers"
            params = {}
            SWIS_query(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)

        elif sys.argv[4] == "query":
            print("[*] query")
            print("[*] parameter:")
            print("    - query ")
            query = input("input the query: (eg. SELECT AccountID FROM Orion.Accounts )")
            params = {}
            SWIS_query(sys.argv[1], sys.argv[2], sys.argv[3], query, **params)
            
        elif sys.argv[4] == "invoke":
            print("[*] invoke")
            print("[*] parameter:")
            print("    - entity")
            print("    - verb")
            print("    - args")
            entity = input("input the entity: (eg. Metadata.Entity )")    
            verb = input("input the verb: (eg. GetAliases )")
            args = input("input the args: (eg. SELECT B.Caption FROM Orion.Nodes B )")
            SWIS_invoke(sys.argv[1], sys.argv[2], sys.argv[3], entity, verb, args)

        elif sys.argv[4] == "create":
            print("[*] create")
            print("[*] parameter:")
            print("    - entity")
            print("    - properties")
            entity = input("input the entity: (eg. Orion.Pollers )")    
            properties = input("input the properties: (eg. {\"PollerType\":\"hi from curl 2\", \"NetObject\":\"N:123\"} )")
            SWIS_create(sys.argv[1], sys.argv[2], sys.argv[3], entity, **json.loads(properties))

        elif sys.argv[4] == "read":
            print("[*] read")
            print("[*] parameter:")
            print("    - uri")
            uri = input("input the uri: (eg. swis://Server1./Orion/Orion.Pollers/PollerID=1 )")
            SWIS_read(sys.argv[1], sys.argv[2], sys.argv[3], uri)

        elif sys.argv[4] == "update":
            print("[*] update")
            print("[*] parameter:")
            print("    - uri")
            print("    - properties")
            uri = input("input the uri: (eg. swis://Server1./Orion/Orion.Pollers/PollerID=1 )")
            properties = input("input the properties: (eg. {\"PollerType\":\"hi from curl\"} )")
            SWIS_update(sys.argv[1], sys.argv[2], sys.argv[3], uri, **json.loads(properties))

        elif sys.argv[4] == "bulkupdate":
            print("[*] bulkupdate")
            print("[*] parameter:")
            print("    - uris")
            print("    - properties")
            uris = input("input the uris: (eg. swis://Server1/Orion/Orion.Nodes/NodeID=1/CustomProperties,swis://Server1/Orion/Orion.Nodes/NodeID=2/CustomProperties )")
            print("uris:")
            print(uris.split(','))
            properties = input("input the properties: (eg. {\"City\": \"Serenity Valley\"} )")
            SWIS_bulkupdate(sys.argv[1], sys.argv[2], sys.argv[3], uris.split(','), **json.loads(properties))

        elif sys.argv[4] == "delete":
            print("[*] delete")
            print("[*] parameter:")
            print("    - uri")
            uri = input("input the uri: (eg. swis://Server1./Orion/Orion.Pollers/PollerID=1 )")
            SWIS_delete(sys.argv[1], sys.argv[2], sys.argv[3], uri)

        elif sys.argv[4] == "bulkdelete":
            print("[*] bulkdelete")
            print("[*] parameter:")
            print("    - uris")
            uris = input("input the uris: (eg. swis://Server1/Orion/Orion.Nodes/NodeID=1/CustomProperties,swis://Server1/Orion/Orion.Nodes/NodeID=2/CustomProperties )")
            print("uris:")
            print(uris.split(','))
            SWIS_bulkdelete(sys.argv[1], sys.argv[2], sys.argv[3], uris.split(','))

            


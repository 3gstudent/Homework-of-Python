#!python3

import ssl
import sys
import base64
import re
import binascii
import os
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
from impacket import ntlm

AddressList = []

def escape(_str):
    _str = _str.replace("&", "&amp;")
    _str = _str.replace("<", "&lt;")
    _str = _str.replace(">", "&gt;")
    _str = _str.replace("\"", "&quot;")
    return _str


def escape2(_str):
    _str = _str.replace("/", "-")
    _str = _str.replace("<", "-l-")
    _str = _str.replace(">", "-g-")
    _str = _str.replace("\"", "-")
    _str = _str.replace(":", "_")    
    return _str


def ntlm_auth_login(host, port, mode, domain, user, data, POST_BODY):
    ews_url = "/EWS/Exchange.asmx"
    if port ==443:
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            session = HTTPSConnection(host, port, context=uv_context)
        except AttributeError:
            session = HTTPSConnection(host, port)
    else:        
        session = HTTPConnection(host, port)

    # Use impacket for NTLM
    if domain == "NULL":
        ntlm_nego = ntlm.getNTLMSSPType1(host)
    else:    
        ntlm_nego = ntlm.getNTLMSSPType1(host, domain)

    #Negotiate auth
    negotiate = base64.b64encode(ntlm_nego.getData())
    # Headers
    headers = {
        "Authorization": 'NTLM %s' % negotiate.decode('utf-8'),
        "Content-type": "text/xml; charset=utf-8",
        "Accept": "text/xml",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    session.request("POST", ews_url, POST_BODY, headers)
    res = session.getresponse()
    res.read()
    if res.status != 401:
        print('Status code returned: %d. Authentication does not seem required for URL'%(res.status))
        sys.exit(0)
    try:
        if 'NTLM' not in res.getheader('WWW-Authenticate'):
            print('NTLM Auth not offered by URL, offered protocols: %s'%(res.getheader('WWW-Authenticate')))
            sys.exit(0)
    except (KeyError, TypeError):
        print('No authentication requested by the server for url %s'%(ews_url))
        sys.exit(0)

    # Get negotiate data
    try:
        ntlm_challenge_b64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.getheader('WWW-Authenticate')).group(1)
        ntlm_challenge = base64.b64decode(ntlm_challenge_b64)
    except (IndexError, KeyError, AttributeError):
        print('No NTLM challenge returned from server')
        sys.exit(0)

    if mode =='plaintext':
        password1 = data;
        nt_hash = ''

    elif mode =='ntlmhash':
        password1 = ''
        nt_hash = binascii.unhexlify(data)

    else:
        print('[!]Wrong parameter')
        sys.exit(0)

    lm_hash = ''

    if domain == "NULL":
        ntlm_auth, _ = ntlm.getNTLMSSPType3(ntlm_nego, ntlm_challenge, user, password1, lm_hash, nt_hash)
    else:    
        ntlm_auth, _ = ntlm.getNTLMSSPType3(ntlm_nego, ntlm_challenge, user, password1, domain, lm_hash, nt_hash)

    auth = base64.b64encode(ntlm_auth.getData())

    headers = {
        "Authorization": 'NTLM %s' % auth.decode('utf-8'),
        "Content-type": "text/xml; charset=utf-8",
        "Accept": "text/xml",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    session.request("POST", ews_url, POST_BODY, headers)
    res = session.getresponse()
    body = res.read()
    session.close()
    return str(res.status), bytes.decode(body)


def find_all_people(host, port, mode, domain, user, data, QueryString):
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
      <m:FindPeople>
         <m:IndexedPageItemView BasePoint="Beginning" MaxEntriesReturned="1000" Offset="0"/>
         <m:ParentFolderId>
            <t:DistinguishedFolderId Id="directory"/>
         </m:ParentFolderId>
         <m:QueryString>{string}</m:QueryString>
      </m:FindPeople>
  </soap:Body>
</soap:Envelope>
'''
    POST_BODY = POST_BODY.format(string=QueryString)
    status, responsetext = ntlm_auth_login(host, port, mode, domain, user, data, POST_BODY)

    if status == "200" and "NoError" in responsetext:
        pattern_name = re.compile(r"<Address>(.*?)</Address>")
        name = pattern_name.findall(responsetext)
        name = list(set(name))                
        for i in range(len(name)): 
            data = name[i]
            x = data.find('<EmailAddress>')
            y = data.find('</EmailAddress>')
            data = data[x+14:y]
            AddressList.append(data)
        return True

    else: 
        print(status)  
        print(responsetext)
        sys.exit(0)


def get_size_of_folder(host, port, mode, domain, user, data, folder):
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetFolder>
      <m:FolderShape>
        <t:BaseShape>Default</t:BaseShape>
      </m:FolderShape>
      <m:FolderIds>
        <t:DistinguishedFolderId Id="{folder}"/>
      </m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>
'''

    POST_BODY = POST_BODY.format(folder = folder)
    status, responsetext = ntlm_auth_login(host, port, mode, domain, user, data, POST_BODY)
    if status == "200" and "NoError" in responsetext:
        pattern_name = re.compile(r"<t:TotalCount>(.*?)</t:TotalCount>")
        name = pattern_name.findall(responsetext)
        if len(name[0]) >0:
          return name[0]
            
    else: 
        print(status)  
        print(responsetext)
        sys.exit(0)


def list_mail_of_folder(host, port, mode, domain, user, data, folder, offset, size):
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>AllProperties</t:BaseShape>
        <t:BodyType>Text</t:BodyType>
      </m:ItemShape>
      <m:IndexedPageItemView MaxEntriesReturned="{size}" Offset="{offset}" BasePoint="Beginning" />
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="{folder}" />
      </m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>
'''
    POST_BODY = POST_BODY.format(folder = folder, size = size, offset = offset)
    status, responsetext = ntlm_auth_login(host, port, mode, domain, user, data, POST_BODY)
    if status == "200" and "NoError" in responsetext:
        pattern_name = re.compile(r"ItemId Id=\"(.*?)</t:HasAttachments>")
        name = pattern_name.findall(responsetext)
        return name
    else: 
        print(status)  
        print(responsetext)
        sys.exit(0)


def save_mail(host, port, mode, domain, user, data, Id, ChangeKey, savepath):
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>AllProperties</t:BaseShape>
        <t:BodyType>Text</t:BodyType>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="{Id}" ChangeKey="{ChangeKey}" />
      </m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>
'''
    POST_BODY = POST_BODY.format(Id = Id, ChangeKey = ChangeKey)
    status, responsetext = ntlm_auth_login(host, port, mode, domain, user, data, POST_BODY)
    if status == "200" and "NoError" in responsetext:
        mailname = Id.replace('/', '-')
        filename = mailname + ".xml"
        filename = savepath + filename
        with open(filename, 'w+', encoding='utf-8') as file_object:
            file_object.write(responsetext)

    else: 
        print(status)  
        print(responsetext)
        sys.exit(0)


def get_attachment(host, port, mode, domain, user, data, ItemId, folderpath):
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Attachments" />
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="{ItemId}" />
      </m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>
'''
    POST_BODY = POST_BODY.format(ItemId = ItemId)
    status, responsetext = ntlm_auth_login(host, port, mode, domain, user, data, POST_BODY)
    if status == "200" and "NoError" in responsetext:
        pattern_name = re.compile(r"<t:AttachmentId Id=\"(.*?)\"/>")
        name = pattern_name.findall(responsetext)
        for i in range(len(name)):
            save_attachment(host, port, mode, domain, user, data, name[i], folderpath)
    else: 
        print(status)  
        print(responsetext)
        sys.exit(0)


def save_attachment(host, port, mode, domain, user, data, AttachmentId, folderpath):
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetAttachment>
      <m:AttachmentIds>
        <t:AttachmentId Id="{AttachmentId}" />
      </m:AttachmentIds>
    </m:GetAttachment>
  </soap:Body>
</soap:Envelope>
'''
    POST_BODY = POST_BODY.format(AttachmentId = AttachmentId)
    status, responsetext = ntlm_auth_login(host, port, mode, domain, user, data, POST_BODY)
    if status == "200" and "NoError" in responsetext:
        pattern_name = re.compile(r"<t:Name>(.*?)</t:Name>")
        name = pattern_name.findall(responsetext)
        print('    Save attachment: %s'%(name[0]))

        pattern_data = re.compile(r"<t:Content>(.*?)</t:Content>")
        attachmentdata = pattern_data.findall(responsetext)

        pattern_type = re.compile(r"<t:ContentType>(.*?)</t:ContentType>")
        contenttype = pattern_type.findall(responsetext)
        name[0] = user + "\\" + folderpath + "\\" + AttachmentId + "-" + name[0]
        if 'text' in contenttype:
            truedata = base64.b64decode(attachmentdata[0])
            with open(name[0], 'w+') as file_object:
                file_object.write(truedata)
        else:
            truedata = base64.b64decode(attachmentdata[0])
            with open(name[0], 'wb+') as file_object:
                file_object.write(truedata)
    else: 
        print(status)  
        print(responsetext)
        sys.exit(0)


def search_mail(host, port, mode, domain, user, data, querystring, folderpath, currentpath):
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:FindItem Traversal='Shallow'>
      <m:ItemShape>
        <t:BaseShape>AllProperties</t:BaseShape>
      </m:ItemShape>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id='{folderpath}'>
        </t:DistinguishedFolderId>
      </m:ParentFolderIds>
      <m:QueryString>{querystring}</m:QueryString>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>
'''
    POST_BODY = POST_BODY.format(querystring = querystring, folderpath = folderpath)
    status, responsetext = ntlm_auth_login(host, port, mode, domain, user, data, POST_BODY)
    if status == "200" and "NoError" in responsetext:
        print("\n[*] Searching " + folderpath)
        pattern_name = re.compile(r"ItemId Id=\"(.*?)</t:HasAttachments>")
        name = pattern_name.findall(responsetext)
        print("[*] Downloading...")
        for i in range(len(name)): 
            print(i, end=",")   
            strlist = name[i].split('\" ChangeKey=\"')
            Id = strlist[0]
            Temp = strlist[1]
            strlist2 = Temp.split('\"/>')
            ChangeKey = strlist2[0]
            save_mail(host, port, mode, domain, user, data, Id, ChangeKey, currentpath+'\\'+user+'\\Search-'+escape2(querystring)+'\\')
            if "HasAttachments>true" in name[i]:
                print('\n[+] %s'%(Id))
                get_attachment(host, port, mode, domain, user, data, Id, 'Search-'+escape2(querystring))
    else: 
        print(status)  
        print(responsetext)
        sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv)!=8:    
        print('ewsManage_Downloader')       
        print('Use to access Exchange Web Service(Support plaintext and ntlmhash)')
        print('Complete daily work automatically')      
        print('Author:3gstudent')      
        print('Reference:https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py')  
        print('Usage:')
        print('%s <host> <port> <mode> <domain> <user> <password> <command>'%(sys.argv[0]))
        print('<mode>:')
        print('- plaintext')   
        print('- ntlmhash')
        print('<command>:')
        print('- download')
        print('- findallpeople')
        print('- search')
        print('Eg.')
        print('%s 192.168.1.1 443 plaintext test.com user1 password1 download'%(sys.argv[0]))
        print('%s test.com 80 ntlmhash NULL user1 c5a237b7e9d8e708d8436b6148a25fa1 findallpeople'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[7] == "findallpeople":
            print('[*]This operation can only be used on Exchange Server 2013 or newer version')
            for i in range(97,123):
                find_all_people(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], chr(i))
            print("[+] GlobalAddressList:")    
            AddressList = list(set(AddressList))
            for i in range(len(AddressList)):
                print("%s"%(AddressList[i]))

        elif sys.argv[7] == "download":
            folderpath = input("Input the folder(inbox/sentitems/inboxall/sentitemsall/other):")
            path1 = os.getcwd()
            path2 = path1 + '\\' + sys.argv[5] + '\\' + folderpath
            if not os.path.exists(path2):     
                os.makedirs(path2)

            if folderpath == "inboxall":
                size = get_size_of_folder(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], "inbox")
                print("[+] inbox size: " + size)
                name = list_mail_of_folder(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], "inbox", 0, size)
               
            elif folderpath == "sentitemsall":
                size = get_size_of_folder(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], "sentitems")
                print("[+] sentitems size: " + size)
                name = list_mail_of_folder(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], "sentitems", 0, size)

            else:
                size = get_size_of_folder(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], folderpath)
                print("[+] %s size: %s"%(folderpath, size))
                offset = input("Input the start position(0):")
                size = input("Input the size:")                
                name = list_mail_of_folder(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], folderpath, offset, size)

            print("[*] Downloading...")
            for i in range(len(name)): 
                print(i, end=",")
                strlist = name[i].split('\" ChangeKey=\"')
                Id = strlist[0]
                Temp = strlist[1]
                strlist2 = Temp.split('\"/>')
                ChangeKey = strlist2[0]
                save_mail(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], Id, ChangeKey, path2+"\\")
                if "HasAttachments>true" in name[i]:
                    print('\n[+] %s'%(Id))
                    get_attachment(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], Id, folderpath)
 
        elif sys.argv[7] == "search":
            print("Eg.")
            print("   size:>100")
            print("   sent:>=2021/1/1 AND sent:<=2021/12/30")
            print("   received:>=2021/1/1 AND received:<=2021/12/30")
            print("   password")
            querystring = input("Input the search string:")
            querystring = escape(querystring)

            path1 = os.getcwd()
            path2 = path1 + '\\' + sys.argv[5] + '\\Search-' + escape2(querystring)
            if not os.path.exists(path2):     
                os.makedirs(path2)

            search_mail(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], querystring, "inbox", path1)
            search_mail(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], querystring, "sentitems", path1)            

        else:
            print("[!] Wrong input")





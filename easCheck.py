import requests
import base64
import sys
import warnings
warnings.filterwarnings("ignore")

def test_options_https(ip,username,password):
    try:
        credential = base64.b64encode(username+":"+password)
        url = 'https://' + ip + '/Microsoft-Server-ActiveSync'
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/vnd.ms-sync.wbxml',
            'Authorization': 'Basic '+credential
        } 
        
        r = requests.options(url, headers = headers, verify = False)
    
        if r.status_code ==200: 
            print('[+] Valid: %s  %s'%(username,password))
            #print(r.headers)
        else:         
            print('[!] Authentication failed')
    except Exception as e:
            print('[!]Error:%s'%e)

        
if __name__ == '__main__':
    if len(sys.argv)!=4:
        print('[!]Wrong parameter')
        print('easCheck')       
        print('Use to check the valid credential of eas(Exchange Server ActiveSync)')    
        print('Usage:')
        print('%s <host> <user> <password>'%(sys.argv[0]))
        print('Eg.')
        print('%s 192.168.1.1 user1 password1'%(sys.argv[0]))
        sys.exit(0)
    else:
        test_options_https(sys.argv[1], sys.argv[2], sys.argv[3])




    
import requests
import sys
import warnings
warnings.filterwarnings("ignore")

def CheckOWA(url, username, password):
    url1 = 'https://'+ url + '/owa/auth.owa'

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    } 
    payload = 'destination=https://%s/owa&flags=4&forcedownlevel=0&username=%s&password=%s&passwordText=&isUtf8=1'%(url, username, password)            
    
    r = requests.post(url1, headers=headers, data=payload, verify = False)
    if 'X-OWA-CANARY' in r.cookies:
        print("[+] Valid:%s  %s"%(username, password))
    else:
        print("[!] Login error")
    r.close()


if __name__ == '__main__':
    if len(sys.argv)!=4:
        print('[!] Wrong parameter')     
        print('checkOWA')       
        print('Use to check the valid account of Exchange by connecting to OWA.')
        print('Author:3gstudent')      
        print('Usage:')
        print('%s <url> <user> <password>'%(sys.argv[0]))
        print('Eg.')
        print('%s 192.168.1.1 user1 password1'%(sys.argv[0]))
        sys.exit(0)
    else:
        CheckOWA(sys.argv[1], sys.argv[2], sys.argv[3])


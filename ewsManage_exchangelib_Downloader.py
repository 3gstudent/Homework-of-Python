#!python3

import sys
import os
from exchangelib import Credentials, Account, Configuration, DELEGATE, FileAttachment, EWSDateTime
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
import urllib3
urllib3.disable_warnings()
import datetime

def escape2(_str):
    _str = _str.replace("/", "-")
    _str = _str.replace("<", "-l-")
    _str = _str.replace(">", "-g-")
    _str = _str.replace("\"", "-")
    _str = _str.replace(":", "_")
    return _str

if __name__ == '__main__':
    if len(sys.argv)!=7:    
        print('ewsManage_exchangelib_Downloader')       
        print('Use exchangelib to access Exchange Web Service(Support plaintext and ntlmhash)')
        print('Requirment: https://github.com/ecederstrand/exchangelib')
        print('Complete daily work automatically')      
        print('Author:3gstudent')      
        print('Reference:https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py')  
        print('Usage:')
        print('%s <host> <mode> <username> <primary_smtp_address> <password> <command>'%(sys.argv[0]))
        print('<mode>:')
        print('- plaintext')   
        print('- ntlmhash')
        print('<command>:')
        print('- download')
        print('- search')
        print('- listfolder')
        print('Eg.')
        print('%s 192.168.1.1 plaintext MYWINDOMAIN\\myuser user1@test.com password1 download'%(sys.argv[0]))
        print('%s outlook.office365.com ntlmhash MYWINDOMAIN\\myuser user1@test.com c5a237b7e9d8e708d8436b6148a25fa1 search'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[6] == "download":

            folderpath = input("Input the folder(inbox/sentitems/inboxall/sentitemsall/other):")
            path1 = os.getcwd()
            path2 = path1 + '\\' + sys.argv[4] + '\\' + folderpath
            if not os.path.exists(path2):     
                os.makedirs(path2)


            if sys.argv[2] == "ntlmhash":
                password = "00000000000000000000000000000000:" + sys.argv[5]
            else:
                password = sys.argv[5]

            credentials = Credentials(sys.argv[3], password)
            config = Configuration(server=sys.argv[1], credentials=credentials)
            email = Account(primary_smtp_address=sys.argv[4], config=config, autodiscover=False, access_type=DELEGATE)
            if email == None:
                print("[!] Login error.")
                sys.exit(0)


            flag = 0      
            if folderpath == "inboxall":
                targetfolder = email.inbox
                size = targetfolder.all().count()
                print("[+] inbox size: " + str(size))
                items = targetfolder.all()
    
            elif folderpath == "sentitemsall":
                targetfolder = email.sent
                size = targetfolder.all().count()
                print("[+] sentitems size: " + str(size))
                items = targetfolder.all()

            elif folderpath == "inbox":
                targetfolder = email.inbox
                size = targetfolder.all().count()
                print("[+] inbox size: " + str(size))
                offset = input("Input the start position(0):")
                size = input("Input the size:")
                items = targetfolder.all()[int(offset):int(offset)+int(size)]
                flag = int(offset)

            elif folderpath == "sentitems":
                targetfolder = email.sent
                size = targetfolder.all().count()
                print("[+] sentitems size: " + str(size))               
                offset = input("Input the start position(0):")
                size = input("Input the size:")
                items = targetfolder.all()[int(offset):int(offset)+int(size)]
                flag = int(offset)

            else:

                targetfolder = email.root.glob(folderpath+"*")
                if targetfolder.folders == []:
                    targetfolder = email.root.glob("*/"+folderpath)
                    if targetfolder.folders == []:
                        targetfolder = email.root.glob("**/"+folderpath)
                        if targetfolder.folders == []:
                            print("[!] Wrong folder")
                            sys.exit(0)

                size = targetfolder.all().count()
                print("[+] %s size: %s"%(folderpath, str(size)))
                offset = input("Input the start position(0):")
                size = input("Input the size:")
                items = targetfolder.all()[int(offset):int(offset)+int(size)]
                flag = int(offset)
               
            print("[*] Downloading...")

            for item in items:
                print(str(flag), end=",")
                flag = flag + 1

                with open(path2 + "\\" + escape2(item.id[-16:]), "w", encoding='utf-8') as fw:
                    fw.write(str(item).replace('\\r\\n','\r\n'))

                for attachment in item.attachments:
                    if isinstance(attachment, FileAttachment):
                        filename = path2 + "\\" + str(escape2(item.id[-16:])) + attachment.name
                        print('\n[+] %s'%(item.id))
                        print("    Save attachment: %s"%str(attachment.name))
                        with open(filename, "wb") as fw:
                            fw.write(attachment.content)

        elif sys.argv[6] == "search":

            mode = input("Input the mode(aqs/string):")
            if mode == "aqs":
                print("Reference:https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/querystring-querystringtype")
                print("Eg.")
                print("   size:>100")
                print("   sent:>=2021/1/1 AND sent:<=2021/12/30")
                print("   received:>=2021/1/1 AND received:<=2021/12/30")

                querystring = input("Input the aqs:")
                path1 = os.getcwd()
                path2 = path1 + '\\' + sys.argv[4] + '\\Search-AQS-' + escape2(querystring)
                if not os.path.exists(path2):     
                    os.makedirs(path2)

                if sys.argv[2] == "ntlmhash":
                    password = "00000000000000000000000000000000:" + sys.argv[5]
                else:
                    password = sys.argv[5]

                credentials = Credentials(sys.argv[3], password)
                config = Configuration(server=sys.argv[1], credentials=credentials)
                email = Account(primary_smtp_address=sys.argv[4], config=config, autodiscover=False, access_type=DELEGATE)
                if email == None:
                    print("[!] Login error.")
                    sys.exit(0)

                print("\n[*] Searching inbox...")
                filtered_items = email.inbox.filter(querystring)
                flag = 0
                for item in filtered_items:                   
                    print(str(flag), end=",")
                    flag = flag + 1

                    with open(path2 + "\\" + escape2(item.id[-16:]), "w", encoding='utf-8') as fw:
                        fw.write(str(item).replace('\\r\\n','\r\n'))

                    for attachment in item.attachments:
                        if isinstance(attachment, FileAttachment):
                            filename = path2 + "\\" + str(escape2(item.id[-16:])) + attachment.name
                            print('\n[+] %s'%(item.id))
                            print("    Save attachment: %s"%str(attachment.name))
                            with open(filename, "wb") as fw:
                                fw.write(attachment.content) 

                print("\n[*] Searching sentitems...")
                filtered_items = email.sent.filter(querystring)
                flag = 0
                for item in filtered_items:                   
                    print(str(flag), end=",")
                    flag = flag + 1

                    with open(path2 + "\\" + escape2(item.id[-16:]), "w", encoding='utf-8') as fw:
                        fw.write(str(item).replace('\\r\\n','\r\n'))

                    for attachment in item.attachments:
                        if isinstance(attachment, FileAttachment):
                            filename = path2 + "\\" + str(escape2(item.id[-16:])) + attachment.name
                            print('\n[+] %s'%(item.id))
                            print("    Save attachment: %s"%str(attachment.name))
                            with open(filename, "wb") as fw:
                                fw.write(attachment.content) 


            elif mode == "string":

                querystring = input("Input the search string:")
                path1 = os.getcwd()
                path2 = path1 + '\\' + sys.argv[4] + '\\Search-String-' + escape2(querystring)
                if not os.path.exists(path2):     
                    os.makedirs(path2)

                if sys.argv[2] == "ntlmhash":
                    password = "00000000000000000000000000000000:" + sys.argv[5]
                else:
                    password = sys.argv[5]

                credentials = Credentials(sys.argv[3], password)
                config = Configuration(server=sys.argv[1], credentials=credentials)
                email = Account(primary_smtp_address=sys.argv[4], config=config, autodiscover=False, access_type=DELEGATE)
                if email == None:
                    print("[!] Login error.")
                    sys.exit(0)

                print("\n[*] Searching inbox...")
                filtered_items = email.inbox.all()
                flag = 0
                for item in filtered_items:
                    if querystring in  str(item):            
                        print(str(flag), end=",")
                        flag = flag + 1

                        with open(path2 + "\\" + escape2(item.id[-16:]), "w", encoding='utf-8') as fw:
                            fw.write(str(item).replace('\\r\\n','\r\n'))

                        for attachment in item.attachments:
                            if isinstance(attachment, FileAttachment):
                                filename = path2 + "\\" + str(escape2(item.id[-16:])) + attachment.name
                                print('\n[+] %s'%(item.id))
                                print("    Save attachment: %s"%str(attachment.name))
                                with open(filename, "wb") as fw:
                                    fw.write(attachment.content)

                print("\n[*] Searching sentitems...")
                filtered_items = email.sent.all()
                flag = 0
                for item in filtered_items:
                    if querystring in  str(item):            
                        print(str(flag), end=",")
                        flag = flag + 1

                        with open(path2 + "\\" + escape2(item.id[-16:]), "w", encoding='utf-8') as fw:
                            fw.write(str(item).replace('\\r\\n','\r\n'))

                        for attachment in item.attachments:
                            if isinstance(attachment, FileAttachment):
                                filename = path2 + "\\" + str(escape2(item.id[-16:])) + attachment.name
                                print('\n[+] %s'%(item.id))
                                print("    Save attachment: %s"%str(attachment.name))
                                with open(filename, "wb") as fw:
                                    fw.write(attachment.content)

        elif sys.argv[6] == "listfolder":
            if sys.argv[2] == "ntlmhash":
                password = "00000000000000000000000000000000:" + sys.argv[5]
            else:
                password = sys.argv[5]

            credentials = Credentials(sys.argv[3], password)
            config = Configuration(server=sys.argv[1], credentials=credentials)
            email = Account(primary_smtp_address=sys.argv[4], config=config, autodiscover=False, access_type=DELEGATE)
            if email == None:
                print("[!] Login error.")
                sys.exit(0)

            print(email.root.tree())

        else:
            print("[!] Wrong input")




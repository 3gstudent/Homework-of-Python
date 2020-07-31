import requests
import json
import re
import sys
import warnings
warnings.filterwarnings("ignore")


def ListFolder(url, username, password, folder, mode):
    session = requests.session()
    url1 = 'https://'+ url + '/owa/auth.owa'

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    } 
    payload = 'destination=https://%s/owa&flags=4&forcedownlevel=0&username=%s&password=%s&passwordText=&isUtf8=1'%(url, username, password)            
    
    r = session.post(url1, headers=headers, data=payload, verify = False)
    print("[*] Try to login")
    if 'X-OWA-CANARY' in r.cookies:
        print("[+] Valid:%s  %s"%(username, password))
    else:
        print("[!] Login error")
        return 0

    print("[*] Try to ListFolder")
    url2 = 'https://'+ url + '/owa/service.svc?action=FindItem'
    headers = {
        'X-OWA-CANARY': r.cookies['X-OWA-CANARY'],
        'Action': 'FindItem',
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    body = {"__type":"FindItemJsonRequest:#Exchange","Header":{"__type":"JsonRequestHeaders:#Exchange","RequestServerVersion":"Exchange2013","TimeZoneContext":{"__type":"TimeZoneContext:#Exchange","TimeZoneDefinition":{"__type":"TimeZoneDefinitionType:#Exchange","Id":"SA Pacific Standard Time"}}},"Body":{"__type":"FindItemRequest:#Exchange","ItemShape":{"__type":"ItemResponseShape:#Exchange","BaseShape":"IdOnly"},"ParentFolderIds":[{"__type":"DistinguishedFolderId:#Exchange","Id":""}],"Traversal":"Shallow","Paging":{"__type":"IndexedPageView:#Exchange","BasePoint":"Beginning","Offset":0,"MaxEntriesReturned":999999},"ViewFilter":"All","ClutterFilter":"All","IsWarmUpSearch":0,"ShapeName":"MailListItem","SortOrder":[{"__type":"SortResults:#Exchange","Order":"Descending","Path":{"__type":"PropertyUri:#Exchange","FieldURI":"DateTimeReceived"}}]}}
    body['Body']['ParentFolderIds'][0]['Id'] = folder

    r = session.post(url2, headers=headers, json = body, verify = False)
    print('[+] TotalItems:' + str(json.loads(r.text)['Body']['ResponseMessages']['Items'][0]['RootFolder']['TotalItemsInView']))

    if mode == 'full':
        print('[+] Try to list the mail.')
        for item in json.loads(r.text)['Body']['ResponseMessages']['Items'][0]['RootFolder']['Items']:
            print('Subject:' + item['Subject'])
            if 'From' in item:
                print('From:' + item['From']['Mailbox']['Name'])
                print('FromEmailAddress:' + item['From']['Mailbox']['EmailAddress'])
            else:
                print('From:' + 'Self')   
            print('DisplayTo:' + item['DisplayTo'])
            print('HasAttachments:' + str(item['HasAttachments']))
            print('IsRead:' + str(item['IsRead']))
            print('DateTimeReceived:' + item['DateTimeReceived'])
            print('ConversationId:' + item['ConversationId']['Id'])
            print('\r\n')
    filename = 'ListFolder_' + folder + ".txt"        
    print('[+] Save the result to %s'%(filename))
    with open(filename, 'w+', encoding='utf-8') as file_object:
        file_object.write(r.text)            
    r.close()


def ViewMail(url, username, password, ConversationId):
    session = requests.session()
    url1 = 'https://'+ url + '/owa/auth.owa'

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    } 
    payload = 'destination=https://%s/owa&flags=4&forcedownlevel=0&username=%s&password=%s&passwordText=&isUtf8=1'%(url, username, password)            
    
    r = session.post(url1, headers=headers, data=payload, verify = False)
    print("[*] Try to login")
    if 'X-OWA-CANARY' in r.cookies:
        print("[+] Valid:%s  %s"%(username, password))
    else:
        print("[!] Login error")
        return 0

    print("[*] Try to ViewMail")
    url2 = 'https://'+ url + '/owa/service.svc?action=GetConversationItems'
    headers = {
        'X-OWA-CANARY': r.cookies['X-OWA-CANARY'],
        'Action': 'GetConversationItems',
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    body = {"__type":"GetConversationItemsJsonRequest:#Exchange","Header":{"__type":"JsonRequestHeaders:#Exchange","RequestServerVersion":"Exchange2013","TimeZoneContext":{"__type":"TimeZoneContext:#Exchange","TimeZoneDefinition":{"__type":"TimeZoneDefinitionType:#Exchange","Id":"SA Pacific Standard Time"}}},"Body":{"__type":"GetConversationItemsRequest:#Exchange","Conversations":[{"__type":"ConversationRequestType:#Exchange","ConversationId":{"__type":"ItemId:#Exchange","Id":""},"SyncState":""}],"ItemShape":{"__type":"ItemResponseShape:#Exchange","BaseShape":"IdOnly","FilterHtmlContent":1,"BlockExternalImagesIfSenderUntrusted":1,"AddBlankTargetToLinks":1,"ClientSupportsIrm":1,"InlineImageUrlTemplate":"data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAEALAAAAAABAAEAAAIBTAA7","MaximumBodySize":2097152,"InlineImageUrlOnLoadTemplate":"InlineImageLoader.GetLoader().Load(this)","InlineImageCustomDataTemplate":"{id}"},"ShapeName":"ItemPartUniqueBody","SortOrder":"DateOrderDescending","MaxItemsToReturn":20}}
    body['Body']['Conversations'][0]['ConversationId']['Id'] = ConversationId

    r = session.post(url2, headers=headers, json = body, verify = False)
    
    for item in json.loads(r.text)['Body']['ResponseMessages']['Items'][0]['Conversation']['ConversationNodes'][0]['Items']:
        print('Subject:' + item['Subject'])
        if 'From' in item:
            print('From:' + item['From']['Mailbox']['Name'])
            print('FromEmailAddress:' + item['From']['Mailbox']['EmailAddress'])
        else:
            print('From:' + 'Self')
        for user in item['ToRecipients']:
            print('ToRecipients:' + user['Name'])
            print('ToRecipientsEmailAddress:' + user['EmailAddress'])
        print('DisplayTo:' + item['DisplayTo'])
        print('HasAttachments:' + str(item['HasAttachments']))
        if item['HasAttachments'] == True:
            for att in item['Attachments']:
                print('  Name:' + att['Name'])
                print('  ContentType:' + att['ContentType'])      
                print('  Id:' + att['AttachmentId']['Id'])    

        print('IsRead:' + str(item['IsRead']))
        print('DateTimeReceived:' + item['DateTimeReceived'])
        print('Body:\r\n' + item['UniqueBody']['Value'])
        print('\r\n')

    filename = 'ViewMail_' + ConversationId + ".txt"        
    print('[+] Save the result to %s'%(filename))
    with open(filename, 'w+', encoding='utf-8') as file_object:
        file_object.write(r.text)             
    r.close()


def DownloadAttachment(url, username, password, Id, mode):
    session = requests.session()
    url1 = 'https://'+ url + '/owa/auth.owa'

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    } 
    payload = 'destination=https://%s/owa&flags=4&forcedownlevel=0&username=%s&password=%s&passwordText=&isUtf8=1'%(url, username, password)            
    
    r = session.post(url1, headers=headers, data=payload, verify = False)
    print("[*] Try to login")
    if 'X-OWA-CANARY' in r.cookies:
        print("[+] Valid:%s  %s"%(username, password))
    else:
        print("[!] Login error")
        return 0

    print("[*] Try to DownloadAttachment")

    url2 = 'https://'+ url + '/owa/service.svc/s/GetFileAttachment?id=' + Id + '&X-OWA-CANARY=' + r.cookies['X-OWA-CANARY']
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    r = session.get(url2, headers=headers, verify = False)
    pattern_name = re.compile(r"\"(.*?)\"")
    name = pattern_name.findall(r.headers['Content-Disposition'])
    print('[+] Attachment name: %s'%(name[0]))

    if mode == 'text':
        with open(name[0], 'w+', encoding='utf-8') as file_object:
            file_object.write(r.text)     

    elif mode == 'raw':
        with open(name[0], 'wb+') as file_object:
            file_object.write(r.content) 

    r.close()          
    


if __name__ == '__main__':
    if len(sys.argv)!=5:
        print('[!] Wrong parameter')     
        print('owaManage')       
        print('Use to read mails by connecting to OWA.')
        print('Author:3gstudent')       
        print('Usage:')
        print('%s <url> <user> <password> <command>'%(sys.argv[0]))
        print('<command>:')    
        print('- ListFolder')
        print('- ViewMail')
        print('- DownloadAttachment') 
        print('Eg.')
        print('%s 192.168.1.1 user1 password1 ListFolder'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[4] == "ListFolder":
            Folder = input("Input the folder:(Eg. inbox/sentitems/deleteditems)")
            Mode = input("Input the output data size:(full or short)")
            ListFolder(sys.argv[1], sys.argv[2], sys.argv[3], Folder, Mode)
        elif sys.argv[4] == "ViewMail":
            ConversationId = input("Input the ConversationId:")
            ViewMail(sys.argv[1], sys.argv[2], sys.argv[3], ConversationId)

        elif sys.argv[4] == "DownloadAttachment":  
            Id = input("Input the Id of the attachment:")    
            Mode = input("Input the file type:(text or raw)")    
            DownloadAttachment(sys.argv[1], sys.argv[2], sys.argv[3], Id, Mode)
        else:
            print('[!] Wrong parameter')            


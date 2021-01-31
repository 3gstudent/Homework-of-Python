import imaplib, string, email
import os, sys
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logfile = './log.txt'
fh = logging.FileHandler(logfile, mode='a')
fh.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
 
logger.addHandler(fh)
logger.addHandler(ch)

def decode_str(s):
    try:
        data = email.header.decode_header(s)
    except:
        logger.error('Header decode error')
        return None 
    sub_bytes = data[0][0] 
    sub_charset = data[0][1]
    if None == sub_charset:
        data = sub_bytes
    elif 'unknown-8bit' == sub_charset:
        data = str(sub_bytes, 'utf8')
    else:
        data = str(sub_bytes, sub_charset)
    return data 

def get_attachments(msg,dirPath):
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        fileName = part.get_filename()
        fileName = decode_str(fileName)
        if bool(fileName):
            saveName = dirPath + "\\" + fileName
            logger.info(saveName)
            with open(saveName,'wb') as f:
                f.write(part.get_payload(decode=True))

def CheckConfig(mail, password, imap_server):
    M = imaplib.IMAP4_SSL(imap_server,"993")
    try:
        M.login(mail,password)
    except Exception as e:
        logger.error(e)
        return False
    else:        
        print("[+]", mail,password)        
        logger.info("[*] Try to get the config")
        data = M.list()
        logger.info(data[0])
        for datatemp in data[1]:
            logger.info(datatemp.decode('utf8'))   
        M.logout()  

def SaveAttachOfInbox(mail, password, imap_server):
    M = imaplib.IMAP4_SSL(imap_server,"993")
    try:
        M.login(mail,password)
    except Exception as e:
        logger.error(e)
        return False
    else:        
        print("[+]", mail,password)
        logger.info("[*] Try to download the attachments of Inbox")

        path1 = os.getcwd()
        path2 = path1 + '\\' + mail + '\\Inbox'
        if not os.path.exists(path2):     
            os.makedirs(path2) 

        M.select('INBOX',False)
        dataInfo = M.status('INBOX','(MESSAGES UNSEEN)')
        logger.info(dataInfo)

        typ, data = M.search(None, 'ALL')
        for num in data[0].split():
            logger.info(num.decode('utf8'))           
            try:
                typ, data = M.fetch(num, '(RFC822)')
                raw = email.message_from_bytes(data[0][1])
                #print(raw)
                get_attachments(raw,path2)
            except Exception as e:
                logger.error(e)
        M.close()        
        M.logout()        

def SaveAttachOfSent(mail, password, imap_server):
    M = imaplib.IMAP4_SSL(imap_server,"993")
    try:
        M.login(mail,password)
    except Exception as e:
        logger.error(e)
        return False
    else:
        print("[+]", mail,password)
        logger.info("[*] Try to download the attachments of Sent")

        path1 = os.getcwd()
        path2 = path1 + '\\' + mail + '\\Sent Items'
        if not os.path.exists(path2):     
            os.makedirs(path2) 
        M.select('"Sent Items"',False)
        dataInfo = M.status('"Sent Items"','(MESSAGES)')
        logger.info(dataInfo)

        typ, data = M.search(None, 'ALL')
        for num in data[0].split():
            logger.info(num.decode('utf8'))
            time.sleep(2)          
            try:
                typ, data = M.fetch(num, '(RFC822)')
                raw = email.message_from_bytes(data[0][1])
                #print(raw)
                get_attachments(raw,path2)                          
            except Exception as e:
                logger.error(e)                
        M.close()
        M.logout()   

def DownloadAllMailOfInbox(mail, password, imap_server):
    M = imaplib.IMAP4_SSL(imap_server,"993")
    try:
        M.login(mail,password)
    except Exception as e:
        logger.error(e)
        return False
    else:        
        print("[+]", mail,password)
        logger.info("[*] Try to get the mail of Inbox")

        path1 = os.getcwd()
        path2 = path1 + '\\' + mail +'\\Inbox'
        if not os.path.exists(path2):     
            os.makedirs(path2) 

        M.select('INBOX',False)
        dataInfo = M.status('INBOX','(MESSAGES UNSEEN)')
        logger.info(dataInfo)

        typ, data = M.search(None,'ALL')
        for num in data[0].split():
            logger.info(num.decode('utf8'))
            time.sleep(2)
            try:
                typ, data = M.fetch(num, '(RFC822)')
                raw = email.message_from_bytes(data[0][1])
                logger.info("From:" + decode_str(raw['From']))
                logger.info("To:" + decode_str(raw['To']))
                logger.info("Subject:" + decode_str(raw['Subject']))
                logger.info("Date:" + decode_str(raw['Date']))
                filename = path2 + "\\" + num.decode('utf8') + ".eml"
                f = open(filename,'wb')
                f.write(bytes(raw))
                f.close
                              
            except Exception as e:
                logger.error(e)             
        M.close()
        M.logout() 

def DownloadAllMailOfSent(mail, password, imap_server):
    M = imaplib.IMAP4_SSL(imap_server,"993")
    try:
        M.login(mail,password)
    except Exception as e:
        logger.error(e)
        return False
    else:        
        print("[+]", mail,password)
        logger.info("[*] Try to get the mail of Sent")

        path1 = os.getcwd()
        path2 = path1 + '\\' + mail + '\\Sent Items'
        if not os.path.exists(path2):     
            os.makedirs(path2) 

        M.select('"Sent Items"',False)
        dataInfo = M.status('"Sent Items"','(MESSAGES)')
        logger.info(dataInfo)

        typ, data = M.search(None,'ALL')
        for num in data[0].split():
            logger.info(num.decode('utf8'))
            time.sleep(2)
            try:
                typ, data = M.fetch(num, '(RFC822)')
                raw = email.message_from_bytes(data[0][1])
                logger.info("From:" + decode_str(raw['From']))
                logger.info("To:" + decode_str(raw['To']))
                logger.info("Subject:" + decode_str(raw['Subject']))
                logger.info("Date:" + decode_str(raw['Date']))
                filename = path2 + "\\" + num.decode('utf8') + ".eml"
                f = open(filename,'wb')
                f.write(bytes(raw))
                f.close
                               
            except Exception as e:
                logger.error(e)             
        M.close()
        M.logout() 

if __name__ == "__main__":
    if len(sys.argv)!=5:
        print("\nUse IMAP to connect to the mail server.")
        print("Author:3gstudent")   
        print("Usage:")
        print("      %s <IMAP server> <username> <password> <command>"%(sys.argv[0]))
        print("command:")
        print("      CheckConfig             get the folder name")   
        print("      SaveAttachOfInbox       save the attachments of Inbox")
        print("      SaveAttachOfSent        save the attachments of Sent")
        print("      DownloadAllMailOfInbox  download all the mails of Inbox")
        print("      DownloadAllMailOfSent   download all the mails of Sent")
        print("Eg:")
        print("      %s 192.168.1.1 user1 password CheckConfig"%(sys.argv[0])) 
        sys.exit(0)
    else:
        if sys.argv[4]=='CheckConfig':
            CheckConfig(sys.argv[2],sys.argv[3],sys.argv[1])
        elif sys.argv[4]=='SaveAttachOfInbox':
            SaveAttachOfInbox(sys.argv[2],sys.argv[3],sys.argv[1])
        elif sys.argv[4]=='SaveAttachOfSent':
            SaveAttachOfSent(sys.argv[2],sys.argv[3],sys.argv[1])
        elif sys.argv[4]=='DownloadAllMailOfInbox':
            DownloadAllMailOfInbox(sys.argv[2],sys.argv[3],sys.argv[1])
        elif sys.argv[4]=='CheckConfig':
            CheckConfig(sys.argv[2],sys.argv[3],sys.argv[1])
        elif sys.argv[4]=='DownloadAllMailOfSent':
            DownloadAllMailOfSent(sys.argv[2],sys.argv[3],sys.argv[1])        
        else:
          print("[!] Wrong parameter")

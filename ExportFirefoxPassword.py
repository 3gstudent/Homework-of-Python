#Reference:
#https://github.com/unode/firefox_decrypt
#https://github.com/Kerisa/BrowserPasswordDump/blob/master/MozillaPwd.py

import os
import ctypes
import json
import base64
from datetime import datetime

firefoxPath = "C:\Program Files\Mozilla Firefox"
profilePath = "C:\\Users\\a\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\2yi8qmhz.default-beta"
JsonConfigPath = profilePath + "\\logins.json"


class SECItem(ctypes.Structure):
    _fields_ = [
    ('type', ctypes.c_int),
    ('data', ctypes.c_char_p),
    ('len', ctypes.c_uint),
    ]

def LoadJsonPwdData():
    entries = []
    with open(JsonConfigPath, "r") as o:
        js = json.load(o)
        for i in range(len(js['logins'])):
            entries.append({
            'username':js['logins'][i]['encryptedUsername'],
            'pwd':js['logins'][i]['encryptedPassword'],
            'timeCreated':js['logins'][i]['timeCreated'],
            'timeLastUsed':js['logins'][i]['timeLastUsed'],
            'timePasswordChanged':js['logins'][i]['timePasswordChanged'],
            'url':js['logins'][i]['hostname']})
        return entries


def Decode(cipher):
    
    data = base64.b64decode(cipher)
    secItem = SECItem()
    cipherItem = SECItem()
    cipherItem.type = 0
    cipherItem.data = data
    cipherItem.len = len(data)
    if NssDll.PK11SDR_Decrypt(ctypes.byref(cipherItem), ctypes.byref(secItem), 0) != 0:
        print('PK11SDR_Decrypt failed')
        raise

    result = ctypes.string_at(secItem.data, secItem.len).decode('utf8')
    return result

def DocodeEntry(entry):
    try:
        entry['timeCreated'] = timestamp_to_strtime(entry['timeCreated'])
        entry['timeLastUsed'] = timestamp_to_strtime(entry['timeLastUsed'])
        entry['timePasswordChanged'] = timestamp_to_strtime(entry['timePasswordChanged'])


        entry['username'] = Decode(entry['username'])
        entry['pwd'] = Decode(entry['pwd'])
    except:
        print('Error when decode [ ' + entry['url'] + ' ]')
        entry['username'] = '<Error>'
        entry['pwd'] = '<Error>'

def checkMasterPassword(MasterPassword):

    mPassword = ctypes.c_char_p()
    mPassword.value = MasterPassword.encode('utf-8')

    #print("[*] Add the Firefox path to the PATH environment variable")
    os.environ["PATH"] = ';'.join([firefoxPath, os.environ["PATH"]])
   
    try:
        NssDll = ctypes.CDLL("nss3.dll")
    except OSError as e:
        print (e)
        return False
    #else:
        #print("[*] Loaded NSS library from %s\\nss3.dll"%firefoxPath)

    #print("[*] NSS_Init")
    if NssDll.NSS_Init(profilePath) != 0:
        print("[!] NSS_Init failed")
        return False

    #print("[*] PK11_GetInternalKeySlot")
    keySlot = NssDll.PK11_GetInternalKeySlot()
    if keySlot == 0:
        print("[!] PK11_GetInternalKeySlot failed")
        return False

    #print("[*] PK11_CheckUserPassword")
    if NssDll.PK11_CheckUserPassword(ctypes.c_int(keySlot), mPassword) != 0:
        print("[!] PK11_CheckUserPassword failed")
        return False

    #print("[*] PK11_Authenticate")
    if NssDll.PK11_Authenticate(keySlot, 1, 0) != 0:
        print("[!] PK11_Authenticate failed")
        return False
    print("[+] The right master password:%s"%MasterPassword)
    return True


def ExportData(MasterPassword):

    mPassword = ctypes.c_char_p()
    mPassword.value = MasterPassword.encode('utf-8')

    #print("[*] Add the Firefox path to the PATH environment variable")
    os.environ["PATH"] = ';'.join([firefoxPath, os.environ["PATH"]])
   
    global NssDll
    try:
        NssDll = ctypes.CDLL("nss3.dll")
    except OSError as e:
        print (e)
        return False
    #else:
        #print("[*] Loaded NSS library from %s\\nss3.dll"%firefoxPath)

    #print("[*] NSS_Init")
    if NssDll.NSS_Init(profilePath) != 0:
        print("[!] NSS_Init failed")
        return False

    #print("[*] PK11_GetInternalKeySlot")
    keySlot = NssDll.PK11_GetInternalKeySlot()
    if keySlot == 0:
        print("[!] PK11_GetInternalKeySlot failed")
        return False

    #print("[*] PK11_CheckUserPassword")
    if NssDll.PK11_CheckUserPassword(ctypes.c_int(keySlot), mPassword) != 0:
        print("[!] PK11_CheckUserPassword failed")
        return False

    #print("[*] PK11_Authenticate")
    if NssDll.PK11_Authenticate(keySlot, 1, 0) != 0:
        print("[!] PK11_Authenticate failed")
        return False

    entries = LoadJsonPwdData()
    for i in range(len(entries)):
        DocodeEntry(entries[i])
        
    print("[+] Success to export the data: ")    
    print entries    
    return True


def timestamp_to_strtime(timestamp):
    return datetime.fromtimestamp(timestamp / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
 

if __name__ == '__main__':
    checkMasterPassword('12345678')
    checkMasterPassword('12345678xxx')
    ExportData('12345678')









    

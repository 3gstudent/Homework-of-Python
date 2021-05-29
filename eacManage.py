#!python3
import requests
import sys
import warnings
import urllib.parse
warnings.filterwarnings("ignore")

def LoginOWA(url, username, password):
    session = requests.session()

    print("[*] Try to login")
    url1 = "https://" + url + "/owa/auth.owa"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    } 
    payload = 'destination=https://%s/owa&flags=4&forcedownlevel=0&username=%s&password=%s&passwordText=&isUtf8=1'%(url, username, password)            

    response = session.post(url1, headers=headers, data=payload, verify = False)

    if 'X-OWA-CANARY' in response.cookies:
        print("[+] Login success")     
    else:
        if "TimezoneSelectedCheck" in response.text:
            print("[+] First login,try to set the display language and home time zone.");
            cookie_obj = requests.cookies.create_cookie(domain=url,name="mkt",value="en-US")
            session.cookies.set_cookie(cookie_obj)
            owa_canary = session.cookies.get_dict()['X-OWA-CANARY']
            url1 = "https://" + url + "/owa/lang.owa"
            payload = 'destination=&localeName=en-US&tzid=Dateline+Standard+Time&saveLanguageAndTimezone=1&X-OWA-CANARY=' + owa_canary          
            headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
            }
            response = session.post(url1, headers=headers, data=payload, verify = False)            
            if response.status_code == 200:
                print("[+] Login success")
            else:
                print("[!] Login error: " + str(response.status_code))
                exit(0)           
        else:
            print("[!] Login error")
            exit(0)

    url2 = "https://" + url + "/ecp/"
    response = session.get(url2, headers=headers, verify = False)  
    msExchEcpCanary = response.cookies['msExchEcpCanary']
    print("    msExchEcpCanary:" + msExchEcpCanary)
    return session,msExchEcpCanary


def ListAdminRoles(url, session, msExchEcpCanary):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    print("[*] Try to list admin roles");
    p = {
        	"msExchEcpCanary": msExchEcpCanary
    	}
    d = {"filter":{"SearchText":""},"sort":{"Direction":0,"PropertyName":"Name"}}

    url3 = "https://" + url + "/ecp/UsersGroups/AdminRoleGroups.svc/GetList"
    response = session.post(url3, headers=headers, params=p, json=d, verify = False)
    dic = response.json()['d']['Output']
    for i in dic:
        print(" -  " + i['Identity']['DisplayName'] + ":" + i['Identity']['RawIdentity'])


def NewAdminRoles(url, session, msExchEcpCanary):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    print("[*] Try to view admin role group");
    p = {
        	"msExchEcpCanary": msExchEcpCanary
    	}
    d = {"filter":{},"sort":{"Direction":0,"PropertyName":"DisplayName"}}

    url3 = "https://" + url + "/ecp/UsersGroups/ManagementRoles.svc/GetList"
    response = session.post(url3, headers=headers, params=p, json=d, verify = False)
    dic = response.json()['d']['Output']   
    for i in dic:
        print(" -  " + i['Identity']['DisplayName'] + ":" + i['Identity']['RawIdentity'])

    print("[*] Set the role you want to assign.");
    print("    Select the data from the output above");
    newRole = input("input the DisplayName: ")   
    newRaw  = input("input the RawIdentity: ")
    newName  = input("input the name of the new AdminRole: ")

    print("[*] Confirm the configuration:")
    print("[*] AdminRole:" + newName)    
    print("    Role:" + newRole + "," + newRaw)

    print("[*] Try to add new AdminRole");
    p = {
        	"msExchEcpCanary": msExchEcpCanary
    	}
    d = {
			"properties":
			{
				"Name":newName,
				"Description":"",
				"AggregatedScope":
				{
					"IsOrganizationalUnit":"false",
					"ID":"00000000-0000-0000-0000-000000000000"
				},
				"Roles":
				[
					{
						"__type":"Identity:ECP",
						"DisplayName":newRole,
						"RawIdentity":newRaw
					}
				],
			}
		}

    url3 = "https://" + url + "/ecp/UsersGroups/AdminRoleGroups.svc/NewObject"
    response = session.post(url3, headers=headers, params=p, json=d, verify = False)
    if newName in response.text:
    	print("[+] Add Success")
    	dic = response.json()['d']['Output']
    	for i in dic:
        	print("    Name: " + i['Identity']['DisplayName'])
        	print("    RawIdentity: " + i['Identity']['RawIdentity'])


def EditAdminRoles(url, session, msExchEcpCanary):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    addUser = input("input the mailbox you want to assign: ")
    print("[*] Try to get the RawIdentity of the mailbox")
    p = {
        	"schema":"MailboxService",
        	"msExchEcpCanary": msExchEcpCanary
    	}
    d = {
			"filter":
			{
				"Parameters":
				{
					"__type":"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
					"SearchText":"[[\"anr\",\"startsWith\",[\"" + addUser + "\"]]]"
				}
			},
			"sort":{}
		}
    url3 = "https://" + url + "/ecp/DDI/DDIService.svc/GetList"
    response = session.post(url3, headers=headers, params=p, json=d, verify = False)
    addUserRawIdentity = ''
    if addUser in response.text:
    	print("[+] Result:")
    	dic = response.json()['d']['Output']
   
    	for i in dic:
        	print(" -  " + i['Identity']['DisplayName'] + "," + i['Identity']['RawIdentity'])
        	addUserRawIdentity = i['Identity']['RawIdentity']

    	if len(dic)>1:        	
            print("[!] You should choose the right mailbox")
            addUser = input("input the mailbox you want to assign: ")
            addUserRawIdentity= input("input the RawIdentity of the mailbox: ")

    if len(addUserRawIdentity) == 0:
        print("[!] wrong user name")      
        exit(0)

    print("[*] Confirm the result:")
    print("[*] DisplayName:" + addUser)    
    print("    RawIdentity:" + addUserRawIdentity)

    ListAdminRoles(url, session, msExchEcpCanary)    
    editRole = input("input the admin role name you want to edit: ")
    editRoleRawIdentity = input("input the RawIdentity: ")
    
    print("[*] Confirm the result:")
    print("[*] AdminRole:" + editRole)    
    print("    RawIdentity:" + editRoleRawIdentity)

    print("[*] Try to edit the AdminRole")
    p = {
            "msExchEcpCanary": msExchEcpCanary
        }
    d = {
			"identity":
			{
				"__type":"Identity:ECP",
				"DisplayName":editRole,
				"RawIdentity":editRoleRawIdentity
			},
			"properties":
			{
				"Members":
				[
					{
						"__type":"Identity:ECP",
						"DisplayName":addUser,
						"RawIdentity":addUserRawIdentity
					}
				],
				"ReturnObjectType":1
			}
		}
    url4 = "https://" + url + "/ecp/UsersGroups/AdminRoleGroups.svc/SetObject"
    response = session.post(url4, headers=headers, params=p, json=d, verify = False)
    if "Update-RoleGroupMember" in response.text:
        print("[+] Edit Success")
    else:
        print(response.text)


def RemoveAdminRoles(url, session, msExchEcpCanary):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    ListAdminRoles(url, session, msExchEcpCanary)    
    removeRole = input("input the admin role name you want to remove: ")
    removeRoleRawIdentity = input("input the RawIdentity: ")

    print("[*] Try to remove admin roles");
    p = {
            "msExchEcpCanary": msExchEcpCanary
        }
    d = {
            "identities":
            [
                {
                    "__type":"Identity:ECP",
                    "DisplayName":removeRole,
                    "RawIdentity":removeRoleRawIdentity
                }
            ],
            "parameters":{}
        }

    url3 = "https://" + url + "/ecp/UsersGroups/AdminRoleGroups.svc/RemoveObjects"
    response = session.post(url3, headers=headers, params=p, json=d, verify = False)

    if len(response.json()['d']['ErrorRecords']) > 0:
        print(response.text)
    else:
        print("[+] Remove Success")


def AddMailbox(url, session, msExchEcpCanary):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    newUser = input("input the new mailbox(use1@mail.com): ")
    newUsername = newUser.split('@')[0]
    newUserpassword = input("input the password: ")

    print("[*] Try to add the new mailbox")     
    p = {
        "schema": "MailboxService",
        "msExchEcpCanary": msExchEcpCanary
    }
    d = {
    "properties":{
        "Parameters":
        {
                "__type":"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "RemoteArchive":"false",
                "UserPrincipalName":newUser,
                "IsNewMailbox":"true",
                "DisplayName":newUsername,
                "Name":newUsername,
                "PlainPassword":newUserpassword,
                "ResetPasswordOnNextLogon":"false",
                "EnableArchive":"false"
        }
    },
    "sort":{}
}
 
    url3 = "https://" + url + "/ecp/DDI/DDIService.svc/NewObject" 
    response = session.post(url3, headers=headers, params=p, json=d, verify = False)
    if len(response.json()['d']['ErrorRecords']) > 0:
        print(response.text)
    else:
        print("[+] Add Success")
        dic = response.json()['d']['Output']
        for i in dic:
            print("    Name: " + i['Identity']['DisplayName'])
            print("    RawIdentity: " + i['Identity']['RawIdentity'])



def RemoveMailbox(url, session, msExchEcpCanary):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"
    }

    removeUser = input("input the mailbox you want to remove: ")
    print("[*] Try to get the RawIdentity of the mailbox")
    p = {
            "schema":"MailboxService",
            "msExchEcpCanary": msExchEcpCanary
        }
    d = {
            "filter":
            {
                "Parameters":
                {
                    "__type":"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                    "SearchText":"[[\"anr\",\"startsWith\",[\"" + removeUser + "\"]]]"
                }
            },
            "sort":{}
        }
    url3 = "https://" + url + "/ecp/DDI/DDIService.svc/GetList"
    response = session.post(url3, headers=headers, params=p, json=d, verify = False)
    removeUserRawIdentity = ''
    if removeUser in response.text:
        print("[+] Result:")
        dic = response.json()['d']['Output']
   
        for i in dic:
            print(" -  " + i['Identity']['DisplayName'] + "," + i['Identity']['RawIdentity'])
            removeUserRawIdentity = i['Identity']['RawIdentity']

        if len(dic)>1:          
            print("[!] You should choose the right mailbox")
            removeUser = input("input the mailbox you want to assign: ")
            removeUserRawIdentity= input("input the RawIdentity of the mailbox: ")

    if len(removeUserRawIdentity) == 0:
        print("[!] wrong user name")      
        exit(0)

    print("[*] Confirm the result:")
    print("[*] DisplayName:" + removeUser)    
    print("    RawIdentity:" + removeUserRawIdentity)

    print("[*] Try to remove the mailbox")     
    p = {
        "workflow": "RemoveMailboxOnPremise",        
        "schema": "MailboxService",
        "msExchEcpCanary": msExchEcpCanary
    }
    d = {
            "identities":
            [

                {
                    "__type":"Identity:ECP",
                    "DisplayName":removeUser,
                    "RawIdentity":removeUserRawIdentity
                }
            ],
            "parameters":{}
        }
 
    url4 = "https://" + url + "/ecp/DDI/DDIService.svc/MultiObjectExecute" 
    response = session.post(url4, headers=headers, params=p, json=d, verify = False)
    print(response.text)
    if len(response.json()['d']['ErrorRecords']) > 0:
        print(response.text)
    else:
        print("[+] Remove Success")


def ExportAllMailbox(url, session, msExchEcpCanary):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx",
        "Content-Type":"application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br"
    }

    print("[*] Try to export all mailboxes")     
    p = {
        "schema": "MailboxService",
        "handlerClass": "ExportCsvHandler",
        "msExchEcpCanary": msExchEcpCanary
    }
    body = {
        "workflowOutput": "DisplayName,PrimarySmtpAddress,Department,HiddenFromAddressListsEnabled,Name,Office,OrganizationalUnit,StateOrProvince,Title",
        "titlesCSV": "DISPLAY NAME,EMAIL ADDRESS,DEPARTMENT,HIDDEN FROM ADDRESS LIST,NAME,OFFICE,ORGANIZATIONAL UNIT,STATE/PROVINCE,TITLE",
        "PropertyList":"DisplayName,PrimarySmtpAddress,Department,HiddenFromAddressListsEnabled,Name,Office,OrganizationalUnit,StateOrProvince,Title"
    }
    postData = urllib.parse.urlencode(body).encode("utf-8")
    url3 = "https://" + url + "/ecp/UsersGroups/Download.aspx" 
    response = session.post(url3, headers=headers, params=p, data=postData, verify = False)
    if response.status_code == 200:
        filename = url + "-ExportAllMailbox.csv"
        print("[*] Saving as " + filename)
        with open(filename, 'w+', encoding='utf-8') as file_object:
            file_object.write(response.text)
    else:
        print(response.status_code)
        print(response.text)


if __name__ == '__main__':
    if len(sys.argv)!=5: 
        print('eacManage')       
        print('Use to access Exchange admin center')
        print('Author:3gstudent')      
        print('Usage:')
        print('%s <url> <user> <password> <command>'%(sys.argv[0]))
        print('<command>:')
        print('- ListAdminRoles')
        print('- NewAdminRoles')  
        print('- EditAdminRoles')
        print('- RemoveAdminRoles')
        print('- AddMailbox')
        print('- RemoveMailbox')
        print('- ExportAllMailbox')               
        print('Eg.')
        print('%s 192.168.1.1 user1 password1 ListAdminRoles'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[4] == "ListAdminRoles":
            session,msExchEcpCanary = LoginOWA(sys.argv[1], sys.argv[2], sys.argv[3])
            print("[*] ListAdminRoles")
            ListAdminRoles(sys.argv[1], session, msExchEcpCanary)

        elif sys.argv[4] == "NewAdminRoles":
            session,msExchEcpCanary = LoginOWA(sys.argv[1], sys.argv[2], sys.argv[3])    
            print("[*] NewAdminRoles")
            NewAdminRoles(sys.argv[1], session, msExchEcpCanary)

        elif sys.argv[4] == "EditAdminRoles":
            session,msExchEcpCanary = LoginOWA(sys.argv[1], sys.argv[2], sys.argv[3])
            print("[*] EditAdminRoles")
            EditAdminRoles(sys.argv[1], session, msExchEcpCanary)

        elif sys.argv[4] == "RemoveAdminRoles": 
            session,msExchEcpCanary = LoginOWA(sys.argv[1], sys.argv[2], sys.argv[3])
            print("[*] RemoveAdminRoles")
            RemoveAdminRoles(sys.argv[1], session, msExchEcpCanary)

        elif sys.argv[4] == "AddMailbox": 
            session,msExchEcpCanary = LoginOWA(sys.argv[1], sys.argv[2], sys.argv[3])
            print("[*] AddMailbox")
            AddMailbox(sys.argv[1], session, msExchEcpCanary)

        elif sys.argv[4] == "RemoveMailbox": 
            session,msExchEcpCanary = LoginOWA(sys.argv[1], sys.argv[2], sys.argv[3])
            print("[*] RemoveMailbox")
            RemoveMailbox(sys.argv[1], session, msExchEcpCanary)

        elif sys.argv[4] == "ExportAllMailbox": 
            session,msExchEcpCanary = LoginOWA(sys.argv[1], sys.argv[2], sys.argv[3])
            print("[*] ExportAllMailbox")
            ExportAllMailbox(sys.argv[1], session, msExchEcpCanary)


        else:
            print("[!] Wrong parameter")            




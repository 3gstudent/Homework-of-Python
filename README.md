# Homework-of-Python
Python codes of my blog.

### pptp_password_hack.py

Use Brute-force attack to get the password of PPTP VPN.

It'll read the passwords in file(named wordlist) and then use pptpsetup to connect to the server.

The time interval is 10 seconds.


### portscan.py

Use to scan port.

The timeout is 3 seconds.

c++ version：

https://github.com/3gstudent/Homework-of-C-Language/blob/master/portscan.cpp

### urltoip.py

Use to get ip from url.

I can use the result of Sublist3r directly.

### file_deduplication(For_urltoip).py

Use to remove duplicate ip from the result of Sublist3r.

I can use the result of urltoip.py directly.

The IP can be sorted by using Sublime(F9).

### file_deduplication.py

Use to remove duplicate items from file.

### Webmin<=1.920-Unauthenticated_RCE(CVE-2019-15107).py

Reference:

https://pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html

### fofa_api.py

Used to call fofa's api and print the IP from the results.

You can get 100 results.

### fofa_api_VIP.py

Used to call fofa's api and print the IP from the results.

If you're VIP,you'll get 10000 results.

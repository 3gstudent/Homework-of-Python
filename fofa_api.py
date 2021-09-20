#python3
import requests
from urllib.parse import urlparse, urljoin, quote
import urllib3
urllib3.disable_warnings()
import sys 
import base64 
import os,json 
email="xx@xx.com"
key="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
def search(keywords): 
    vulhostlist = [] 
    urlenkeywords = quote(keywords)    
    searchurl = "https://fofa.so/api/v1/search/all?email="+email+"&key="+key+"&qbase64="+base64.b64encode(keywords.encode("utf-8")).decode('utf8')
    print(searchurl)
    req = requests.get(searchurl, verify=False)
    data = req.json()
    for ip in data["results"]:
        print(ip[0])
     
if __name__ == "__main__": 
    if len(sys.argv)!=2:
        print ('[!]Wrong parameter') 
        sys.exit() 
    else: 
        search(sys.argv[1])
        

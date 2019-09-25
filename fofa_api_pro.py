import urllib2
import sys 
import base64 
import os,json 
email="xx@xx.com"
key="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
def search(keywords): 
    vulhostlist=[] 
    urlenkeywords=urllib2.quote(keywords)    
    searchurl="https://fofa.so/api/v1/search/all?email="+email+"&key="+key+"&size=10000"+"&qbase64="+base64.b64encode(keywords)

    req=urllib2.urlopen(searchurl)
    results=req.read()
    data=json.loads(results)
    for ip in data["results"]:
        print ip[0]
     
if __name__=="__main__": 
    if len(sys.argv)!=2:
        print ('[!]Wrong parameter') 
        sys.exit() 
    else: 
        search(sys.argv[1])

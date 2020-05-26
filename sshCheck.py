import paramiko
import sys
def sshcheck(hostname, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, port, username, password, timeout=10)
        print("[+] Valid: %s  %s"%(username,password))
        ssh.close();
    except paramiko.AuthenticationException:
        print("[!] Authentication failed")
    except Exception:
        print("[!] Connection Failed")
    except paramiko.SSHException:
        print("[!] Unable to establish SSH connection: %s"%(sshException))

def sshcheckfile(hostname, port, username, keyfile):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    key=paramiko.RSAKey.from_private_key_file(keyfile)
    try:
        ssh.connect(hostname, port, username, pkey=key, timeout=2)
        print("[+] Valid: %s  %s"%(username,keyfile))
        ssh.close();
    except paramiko.AuthenticationException:
        print("[!] Authentication failed")
    except Exception:
        print("[!] Connection Failed")
    except paramiko.SSHException:
        print("[!] Unable to establish SSH connection: %s"%(sshException))

if __name__ == "__main__":
    if len(sys.argv)!=6:
        print('[!]Wrong parameter')     
        print('sshCheck')       
        print('Use to check the valid credential of SSH(Support password and privatekeyfile)')
        print('Author:3gstudent')      
        print('Usage:')
        print('%s <host> <port> <mode><user> <password>'%(sys.argv[0]))
        print('<mode>:')
        print('- plaintext')   
        print('- keyfile')
        print('Eg.')
        print('%s 192.168.1.1 22 plaintext root toor'%(sys.argv[0]))
        print('%s 192.168.1.1 22 keyfile root id_rsa'%(sys.argv[0]))
        sys.exit(0)
    else:
        if sys.argv[3] == 'plaintext': 
            sshcheck(sys.argv[1], int(sys.argv[2]), sys.argv[4], sys.argv[5])
        elif sys.argv[3] == 'keyfile': 
            sshcheckfile(sys.argv[1], int(sys.argv[2]), sys.argv[4], sys.argv[5])


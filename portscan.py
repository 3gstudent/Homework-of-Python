import socket
import sys
Timeout = 3.0

def scan(ip,port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(Timeout)
    try:
        server.connect((ip,port))
        print '%s:%s'%(ip,port)
    except Exception as err:
        print('%s'%(ip))
    finally:
        server.close()
 
if __name__ == '__main__':
    if len(sys.argv)!=4:
    	print '[!]Wrong parameter'
	print 'Usage:'
	print '%s <port> <BeginIP> <EndIP>'%(sys.argv[0])
        sys.exit(0)
    else:
        Port = int(sys.argv[1])
        BeginIP = sys.argv[2]
        EndIP = sys.argv[3]
        
        try:
            socket.inet_aton(BeginIP)
            socket.inet_aton(EndIP)
        except:
            print "[!]input error"
            sys.exit(0)
            
        IPRange = BeginIP[0:BeginIP.rfind('.')]
        begin = BeginIP[BeginIP.rfind('.') + 1:]
        end = EndIP[EndIP.rfind('.') + 1:]
        for i in range(int(begin), int(end)+1):
            strIP = "%s.%s" % (IPRange, i)
            scan(strIP,Port)

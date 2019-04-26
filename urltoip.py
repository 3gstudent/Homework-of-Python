from socket import gethostbyname
import sys
def urltoip(urlpath):
  with open(urlpath,'r') as f:
    for line in f.readlines():
      print('[+]'+ line.strip('\n')),
      try:
        host = gethostbyname(line.strip('\n'))
      except Exception as e:
        with open('error.txt','a+') as ERR:
          ERR.write(line.strip()+ '\n')
          print('error')
      else:
        with open('result.txt','a+') as r:
          r.write(line.strip('\n') + ' ')
          r.write(host + '\n')
          print(host)
  print("[*]done")          

if __name__ == '__main__':
  if len(sys.argv)!=2:
    print('[!]Wrong parameter')
    print('Usage:')
    print('%s <urlpath>'%(sys.argv[0]))
    sys.exit(0)
  else:
    urltoip(sys.argv[1])








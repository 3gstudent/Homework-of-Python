import shutil,sys
def filededuplication(path):
  lines_seen = set()
  outfile=open(path+"new","w")
  f = open(path,"r")
  for line in f:
    if line not in lines_seen:
      outfile.write(line)
      lines_seen.add(line)
  outfile.close()
  print("[*]done")

if __name__ == '__main__':
  if len(sys.argv)!=2:
    print('[!]Wrong parameter')
    print('Usage:')
    print('%s <filepath>'%(sys.argv[0]))
    sys.exit(0)
  else:
    filededuplication(sys.argv[1])

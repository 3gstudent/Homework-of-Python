import shutil,sys
def filededuplication(path):
  lines_seen = set()
  outfile=open(path+"new","w")
  f = open(path,"r")
  for line in f:
    if line.split()[1] not in lines_seen:
      outfile.write(line.split()[1] + "\n")
      lines_seen.add(line.split()[1])
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

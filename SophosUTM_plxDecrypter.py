#Python3 
import os
import sys
import struct
import zlib

def yank(path):
    with open(path, 'r+b') as f:
        f.seek(-12, 2)
        magic_chunk = f.read(12)
        pointer_header = struct.unpack('<III', magic_chunk)
        assert(pointer_header[0] == 0xab2155bc)
        f.seek(-12 - pointer_header[2], 2)
        data = f.read(pointer_header[2])
        outpath1 = "Stage1-" + path
        print("[*] Try to generate " + outpath1)
        with open(outpath1, 'wb') as outf:
            outf.write(data)

def bfs(path):
    outpath1 = "Stage1-" + path
    outpath2 = "Stage2-" + path
    print("[*] Try to generate " + outpath2)
    with open(outpath1, 'rb') as f, open(outpath2, 'wb') as f2:
        header = f.read(4 * 4)
        sig, unk, size, data_offset = struct.unpack('<IIII', header)
        size_data = size - data_offset
        f.seek(data_offset, os.SEEK_SET)
        while True:
            b = f.read(4)
            if len(b) != 4:
                break
            v = struct.unpack('<I', b)[0]
            v ^= size
            f2.write(struct.pack('<I', v))

def snap_dword(pos):
    if pos % 4 != 0:
        return 4 - (pos & 3)
    else:
        return 0

def bfs_extract(path):
    outpath2 = "Stage2-" + path
    outpath3 = "Export-" + path
    with open(outpath2, 'rb') as f:
        paths = []
        pos = 0x20
        f.seek(pos, os.SEEK_SET)
        try:
            while True:
                path_len = struct.unpack('<H', f.read(2))[0]
                pos += 2
                if path_len == 0:
                    break
                path = bytes([b ^ 0xea for b in f.read(path_len)]).decode('ascii')
                print(f'Found file {path}')
                pos += path_len
                pos_delta = snap_dword(pos)
                pos += pos_delta
                f.seek(pos_delta, os.SEEK_CUR)
                offset = struct.unpack('<I', f.read(4))[0]
                pos += 4
                print(f'    Offset: {offset:x}')
                paths.append((path, offset))
        except Exception as e:
            pass

        print("[*] Try to generate " + outpath3)    
        for path_offset in paths:
            path, offset = path_offset
            f.seek(offset, os.SEEK_SET)
            header = f.read(4 * 3)
            len_decompressed, len_data, unk = struct.unpack('<III', header)
            print(f'Extracting {path}')
            print(f'    Offset: {pos:x}')
            print(f'    Length (decompressed): {len_decompressed:x}')
            print(f'    Length (data): {len_data:x}')
            print(f'    Unknown: {unk:x}')
            path_components = path.split('/')
            dir_path = os.path.join(outpath3, *path_components[:-1])
            file_path = os.path.join(outpath3, *path_components) 
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            data = f.read(len_data)
            with open(file_path, 'wb') as f2:
                if unk & 1 == 0:
                    print('    obfuscated data')
                    f2.write(bytes([b ^ 0xea for b in data]))
                else:
                    print('    compressed data')
                    f2.write(bytes([b ^ 0xea for b in zlib.decompress(data)]))

if __name__ == '__main__':
    if len(sys.argv)!=2: 
        print('SophosUTM_plxDecrypter')       
        print('Use to decrypt the .plx file of Sophos UTM')
        print('Reference:')
        print('https://www.atredis.com/blog/2021/8/18/sophos-utm-cve-2020-25223')
        print('https://github.com/the6p4c/bfs_extract')
        print('Usage:')
        print('%s <plx file>'%(sys.argv[0]))
        print('Eg.')
        print('%s confd.plx'%(sys.argv[0]))
        sys.exit(0)
    else:
        yank(sys.argv[1])
        bfs(sys.argv[1])
        bfs_extract(sys.argv[1])
        print("[*] All done.")



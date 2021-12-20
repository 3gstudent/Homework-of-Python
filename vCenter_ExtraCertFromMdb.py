#!/usr/bin/env python3

import base64
import sys
idp_cert_flag = b'\x30\x82\x04'
trusted_cert1_flag = b'\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x31\x2c\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x43\x68\x61\x69\x6e\x73\x2c' # cn=TrustedCertChain-1,cn=TrustedCertificateChains,
trusted_cert2_flag = b'\x01\x00\x12\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x31' # \x01\x00\x12TrustedCertChain-1
not_it_list = [b'Engineering', b'California', b'object']

import numbers
import re
import binascii
import mmap
import os

bytealigned = False
CACHE_SIZE = 1000

class ConstByteStore(object):
    def __init__(self, data, bitlength=None, offset=None):
        self._rawarray = data
        if offset is None:
            offset = 0
        if bitlength is None:
            bitlength = 8 * len(data) - offset
        self.offset = offset
        self.bitlength = bitlength

    def getbyteslice(self, start, end):
        c = self._rawarray[start:end]
        return c

    def _appendstore(self, store):
        if store.offset:
            joinval = (self._rawarray.pop() & (255 ^ (255 >> store.offset)) |
                       (store.getbyte(0) & (255 >> store.offset)))
            self._rawarray.append(joinval)
            self._rawarray.extend(store._rawarray[1:])
        else:
            self._rawarray.extend(store._rawarray)
        self.bitlength += store.bitlength

class MmapByteArray(object):
    def __init__(self, source, bytelength=None, byteoffset=None):
        self.source = source
        source.seek(0, os.SEEK_END)
        self.filelength = source.tell()
        if byteoffset is None:
            byteoffset = 0
        if bytelength is None:
            bytelength = self.filelength - byteoffset
        self.byteoffset = byteoffset
        self.bytelength = bytelength
        self.filemap = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)

    def __getitem__(self, key):
        try:
            start = key.start
            stop = key.stop
        except AttributeError:
            try:
                assert 0 <= key < self.bytelength
                return ord(self.filemap[key + self.byteoffset])
            except TypeError:
                # for Python 3
                return self.filemap[key + self.byteoffset]
        else:
            if start is None:
                start = 0
            if stop is None:
                stop = self.bytelength
            assert key.step is None
            assert 0 <= start < self.bytelength
            assert 0 <= stop <= self.bytelength
            s = slice(start + self.byteoffset, stop + self.byteoffset)
            return bytearray(self.filemap.__getitem__(s))

    def __len__(self):
        return self.bytelength

BYTE_REVERSAL_DICT = dict()

for i in range(256):
    BYTE_REVERSAL_DICT[i] = bytes([int("{0:08b}".format(i)[::-1], 2)])
from io import IOBase as file
xrange = range
basestring = str

INIT_NAMES = ('bytes', 'bool')

TOKEN_RE = re.compile(r'(?P<name>' + '|'.join(INIT_NAMES) +
                      r')(:(?P<len>[^=]+))?(=(?P<value>.*))?$', re.IGNORECASE)

LITERAL_RE = re.compile(r'(?P<name>0([xob]))(?P<value>.+)', re.IGNORECASE)
_tokenname_to_initialiser = {'0x': 'hex'}

def tokenparser(fmt, keys=None, token_cache={}):
    token_key = (fmt, keys)
    meta_tokens = (''.join(f.split()) for f in fmt.split(','))
    return_values = []
    stretchy_token = False
    for meta_token in meta_tokens:
        factor = 1  
        tokens = [meta_token]
        ret_vals = []
        for token in tokens:
            if keys and token in keys:
                ret_vals.append([token, None, None])
                continue
            value = length = None
            if token == '':
                continue
            m = LITERAL_RE.match(token)
            if m:
                name = m.group('name')
                value = m.group('value')
                ret_vals.append([name, length, value])
                continue
            m1 = TOKEN_RE.match(token)
            if m1:
                name = m1.group('name')
                length = m1.group('len')
                if m1.group('value'):
                    value = m1.group('value')

            if length is not None:
                try:
                    length = int(length)
                    if length < 0:
                        raise Error
                    if name == 'bytes':
                        length *= 8
                except Error:
                    raise ValueError("Can't read a token with a negative length.")
                except ValueError:
                    if not keys or length not in keys:
                        raise ValueError("Don't understand length '{0}' of token.".format(length))
            ret_vals.append([name, length, value])
        return_values.extend(ret_vals * factor)
    return_values = [tuple(x) for x in return_values]
    token_cache[token_key] = stretchy_token, return_values
    return stretchy_token, return_values

class Bits(object):
    def __new__(cls, auto=None, length=None, offset=None, _cache={}, **kwargs):
        try:
            if isinstance(auto, basestring):
                try:
                    return _cache[auto]
                except KeyError:
                    x = object.__new__(Bits)
                    try:
                        _, tokens = tokenparser(auto)
                    except ValueError as e:
                        raise CreationError(*e.args)
                    if offset is not None:
                        raise CreationError("offset should not be specified when using string initialisation.")
                    if length is not None:
                        raise CreationError("length should not be specified when using string initialisation.")
                    x._datastore = ConstByteStore(bytearray(0), 0, 0)
                    for token in tokens:
                        x._datastore._appendstore(Bits._init_with_token(*token)._datastore)
                    if len(_cache) < CACHE_SIZE:
                        _cache[auto] = x
                    return x
            if type(auto) == Bits:
                return auto
        except TypeError:
            pass
        x = super(Bits, cls).__new__(cls)
        x._datastore = ConstByteStore(b'')
        x._initialise(auto, length, offset, **kwargs)
        return x

    def _initialise(self, auto, length, offset, **kwargs):

        if auto is not None:
            self._initialise_from_auto(auto, length, offset)
            return
        if not kwargs:
            if length is not None and length != 0:
                data = bytearray((length + 7) // 8)
                self._setbytes_unsafe(data, length, 0)
                return
            self._setbytes_unsafe(bytearray(0), 0, 0)
            return
        k, v = kwargs.popitem()
        try:
            init_without_length_or_offset[k](self, v)
            if length is not None or offset is not None:
                raise CreationError("Cannot use length or offset with this initialiser.")
        except KeyError:
            offset = 0

    def _initialise_from_auto(self, auto, length, offset):
        if offset is None:
            offset = 0
        self._setauto(auto, length, offset)
        return

    @classmethod
    def _init_with_token(cls, name, token_length, value):
        try:
            b = cls(**{_tokenname_to_initialiser[name]: value})
        except KeyError:
            raise CreationError("Can't parse token name {0}.", name)
        return b

    def _setauto(self, s, length, offset):

        if isinstance(s, file):
            if offset is None:
                offset = 0
            if length is None:
                length = os.path.getsize(s.name) * 8 - offset
            byteoffset, offset = divmod(offset, 8)
            bytelength = (length + byteoffset * 8 + offset + 7) // 8 - byteoffset
            m = MmapByteArray(s, bytelength, byteoffset)
            if length + byteoffset * 8 + offset > m.filelength * 8:
                raise CreationError("File is not long enough for specified "
                                    "length and offset.")
            self._datastore = ConstByteStore(m, length, offset)
            return

        if isinstance(s, (bytes, bytearray)):
            self._setbytes_unsafe(bytearray(s), len(s) * 8, 0)
            return

    def _setbytes_safe(self, data, length=None, offset=0):
        data = bytearray(data)
        if length is None:
            length = len(data)*8 - offset
            self._datastore = ByteStore(data, length, offset)
        else:
            if length + offset > len(data) * 8:
                msg = "Not enough data present. Need {0} bits, have {1}."
                raise CreationError(msg, length + offset, len(data) * 8)
            if length == 0:
                self._datastore = ByteStore(bytearray(0))
            else:
                self._datastore = ByteStore(data, length, offset)

    def _setbytes_unsafe(self, data, length, offset):
        self._datastore = type(self._datastore)(data[:], length, offset)

    def _readbytes(self, length, start):
        assert length % 8 == 0
        assert start + length <= self.len
        if not (start + self._offset) % 8:
            return bytes(self._datastore.getbyteslice((start + self._offset) // 8,
                                                      (start + self._offset + length) // 8))
        return self._slice(start, start + length).tobytes()

    def _getbytes(self):
        if self.len % 8:
            raise InterpretError("Cannot interpret as bytes unambiguously - "
                                 "not multiple of 8 bits.")
        return self._readbytes(self.len, 0)

    def _readbin(self, length, start):

        startbyte, startoffset = divmod(start + self._offset, 8)
        endbyte = (start + self._offset + length - 1) // 8
        b = self._datastore.getbyteslice(startbyte, endbyte + 1)
        c = "{:0{}b}".format(int(binascii.hexlify(b), 16), 8*len(b))
        return c[startoffset:startoffset + length]

    def _getbin(self):
        return self._readbin(self.len, 0)

    def _sethex(self, hexstring):
        hexstring = hexstring.replace('0x', '')
        length = len(hexstring)
        if length % 2:
            hexstring += '0'
        try:
            data = bytearray.fromhex(hexstring)
        except ValueError:
            raise CreationError("Invalid symbol in hex initialiser.")
        self._setbytes_unsafe(data, length * 4, 0)

    def _getoffset(self):
        return self._datastore.offset

    def _getlength(self):
        return self._datastore.bitlength

    def _slice_msb0(self, start, end):
        if end == start:
            return self.__class__()
        assert start < end, "start={0}, end={1}".format(start, end)
        offset = self._offset
        startbyte, newoffset = divmod(start + offset, 8)
        endbyte = (end + offset - 1) // 8
        bs = self.__class__()
        bs._setbytes_unsafe(self._datastore.getbyteslice(startbyte, endbyte + 1), end - start, newoffset)
        return bs

    def _readtoken(self, name, pos, length):
        if length is not None and int(length) > self.length - pos:
            raise ReadError("Reading off the end of the data. "
                            "Tried to read {0} bits when only {1} available.".format(int(length), self.length - pos))
        try:
            val = name_to_read[name](self, length, pos)
            return val, pos + length
        except KeyError:
            if name == 'pad':
                return None, pos + length
            raise ValueError("Can't parse token {0}:{1}".format(name, length))
        except TypeError:
            return name_to_read[name](self, pos)

    def _validate_slice_msb0(self, start, end):
        if start is None:
            start = 0
        elif start < 0:
            start += self.len
        if end is None:
            end = self.len
        elif end < 0:
            end += self.len
        if not 0 <= end <= self.len:
            raise ValueError("end is not a valid position in the bitstring.")
        if not 0 <= start <= self.len:
            raise ValueError("start is not a valid position in the bitstring.")
        if end < start:
            raise ValueError("end must not be less than start.")
        return start, end

    def _findbytes(self, bytes_, start, end, bytealigned):
        assert self._datastore.offset == 0
        assert bytealigned is True
        bytepos = (start + 7) // 8
        found = False
        p = bytepos
        finalpos = end // 8
        increment = max(1024, len(bytes_) * 10)
        buffersize = increment + len(bytes_)
        while p < finalpos:
            buf = bytearray(self._datastore.getbyteslice(p, min(p + buffersize, finalpos)))
            pos = buf.find(bytes_)
            if pos != -1:
                found = True
                p += pos
                break
            p += increment
        if not found:
            return ()
        return (p * 8,)

    def _findregex(self, reg_ex, start, end, bytealigned):
        p = start
        length = len(reg_ex.pattern)
        increment = max(4096, length * 10)
        buffersize = increment + length
        while p < end:
            buf = self._readbin(min(buffersize, end - p), p)
            m = reg_ex.search(buf)
            if m:
                pos = m.start()
                if not bytealigned or (p + pos) % 8 == 0:
                    return (p + pos,)
                if bytealigned:
                    p += pos + 1
                    continue
            p += increment
        return ()

    def find(self, bs, start=None, end=None, bytealigned=None):
        return self._find(bs, start, end, bytealigned)

    def _find_msb0(self, bs, start=None, end=None, bytealigned=None):
        bs = Bits(bs)
        if not bs.len:
            raise ValueError("Cannot find an empty bitstring.")
        start, end = self._validate_slice(start, end)
        if bytealigned is None:
            bytealigned = globals()['bytealigned']
        if bytealigned and not bs.len % 8 and not self._datastore.offset:
            p = self._findbytes(bs.bytes, start, end, bytealigned)
        try:
            self._pos = p[0]
        except (AttributeError, IndexError):
            pass
        return p

    def findall(self, bs, start=None, end=None, count=None, bytealigned=None):
        if count is not None and count < 0:
            raise ValueError("In findall, count must be >= 0.")
        bs = Bits(bs)
        start, end = self._validate_slice(start, end)
        if bytealigned is None:
            bytealigned = globals()['bytealigned']
        c = 0
        f = self._findregex
        x = re.compile(bs._getbin())
        while True:

            p = f(x, start, end, bytealigned)
            if not p:
                break
            if count is not None and c >= count:
                return
            c += 1
            try:
                self._pos = p[0]
            except AttributeError:
                pass
            yield p[0]
            if bytealigned:
                start = p[0] + 8
            else:
                start = p[0] + 1
            if start >= end:
                break
        return

    _offset = property(_getoffset)

    len = property(_getlength,
                   doc="""The length of the bitstring in bits. Read only.
                      """)
    length = property(_getlength,
                      doc="""The length of the bitstring in bits. Read only.
                      """)

    bytes = property(_getbytes,
                     doc="""The bitstring as a bytes object. Read only.
                      """)

class ConstBitStream(Bits):
    def _setbitpos(self, pos):
        if pos < 0:
            raise ValueError("Bit position cannot be negative.")
        if pos > self.len:
            raise ValueError("Cannot seek past the end of the data.")
        self._pos = pos

    def _getbitpos(self):
        return self._pos

    def read(self, fmt):
        if isinstance(fmt, numbers.Integral):
            if fmt < 0:
                raise ValueError("Cannot read negative amount.")
            if fmt > self.len - self._pos:
                raise ReadError("Cannot read {0} bits, only {1} available.",
                                fmt, self.len - self._pos)
            bs = self._slice(self._pos, self._pos + fmt)
            self._pos += fmt
            return bs
        p = self._pos
        _, token = tokenparser(fmt)
        if len(token) != 1:
            self._pos = p
            raise ValueError("Format string should be a single token, not {0} "
                             "tokens - use readlist() instead.".format(len(token)))
        name, length, _ = token[0]
        if length is None:
            length = self.len - self._pos
        value, self._pos = self._readtoken(name, self._pos, length)
        return value

    def readto(self, bs, bytealigned=None):

        if isinstance(bs, numbers.Integral):
            raise ValueError("Integers cannot be searched for")
        bs = Bits(bs)
        oldpos = self._pos
        p = self.find(bs, self._pos, bytealigned=bytealigned)
        if not p:
            raise ReadError("Substring not found")
        self._pos += bs.len
        return self._slice(oldpos, self._pos)

    pos = property(_getbitpos, _setbitpos,
                   doc="""The position in the bitstring in bits. Read and write.
                      """)

_lsb0 = False
name_to_read = {}

def _switch_lsb0_methods(lsb0):

    Bits._find = Bits._find_msb0
    Bits._slice = Bits._slice_msb0
    Bits._readuint = None

    Bits._validate_slice = Bits._validate_slice_msb0

    global name_to_read
    name_to_read = {'bytes': Bits._readbytes}

def set_lsb0(v=True):
    _switch_lsb0_methods(v)

def set_msb0(v=True):
    set_lsb0(not v)

set_msb0()
init_without_length_or_offset = {'hex': Bits._sethex}

def writepem(bytes):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    key = "-----BEGIN CERTIFICATE-----\r\n" + data + "\r\n-----END CERTIFICATE-----"
    return key

def writekey(bytes):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    key = "-----BEGIN PRIVATE KEY-----\r\n" + data + "\r\n-----END PRIVATE KEY-----"
    with open("idp_cert.txt", "w") as fw:
        fw.write(key)
    print('[*] Extracted IdP certificate:')
    print(key + '\r\n')
    return key

def check_key_valid(key):
    lines = key.splitlines()
    if lines[1].startswith('MI'):
        return True
    else:
        return False

def get_idp_cert(stream):
    tup = stream.findall(idp_cert_flag, bytealigned=True)
    matches = list(tup)
    for match in matches:
        stream.pos = match - 32
        flag = stream.read('bytes:3')
        if flag == b'\x00\x01\x04':
            size_hex = stream.read('bytes:1')
            size_hex = b'\x04' + size_hex
            size = int(size_hex.hex(), 16)
            #cert_bytes = stream.read(f'bytes:{size}')
            cert_bytes = stream.read('bytes:{}'.format(size))


            if any(not_it in cert_bytes for not_it in not_it_list):
                continue

            key = writekey(cert_bytes)
            if not check_key_valid(key):
                continue
 
            print('[*] Successfully extracted the IdP certificate')        
            return key
    else:
        print('[-] Failed to find the IdP certificate')
        sys.exit()

def get_domain_from_cn(cn):
    parts = cn.split(',')
    domain_parts = [ part.lstrip('dc=').lstrip('DC=').strip() for part in parts if 'dc=' in part.lower() ]
    domain = '.'.join(domain_parts).strip()
    domain = ''.join(char for char in domain)
    return domain

def get_trusted_cert1(stream):
    tup = stream.findall(trusted_cert1_flag)
    matches = list(tup)
    if matches:
        for match in matches:
            stream.pos = match

            cn_end = stream.readto('0x000013', bytealigned=True)
            cn_end_pos = stream.pos

            stream.pos = match
            cn_len = int((cn_end_pos - match - 8) / 8)
            cn = stream.read('bytes:{}'.format(cn_len)).decode()
            domain = get_domain_from_cn(cn)
            if domain:
                print('[*] CN: ' + cn)
                print('[*] Domain: '+ domain)
            else:
                print('[!] Failed parsing domain from CN')
                sys.exit()

            cn = stream.readto('0x0002', bytealigned=True)

            cert1_size_hex = stream.read('bytes:2')
            cert1_size = int(cert1_size_hex.hex(), 16)
            cert1_bytes = stream.read('bytes:{}'.format(cert1_size))

            if b'ssoserverSign' not in cert1_bytes:
                continue
      
            cert1 = writepem(cert1_bytes)
            if not check_key_valid(cert1):
                continue

            print('[*] Successfully extracted trusted certificate 1')
            return cert1
    else:
        print('[-] Failed to find the trusted certificate 1 flags')

def get_trusted_cert2(stream):
    tup = stream.findall(trusted_cert2_flag)
    matches = list(tup)
    for match in matches:
        stream.pos = match - 10240

        try:
            start = stream.readto('0x308204', bytealigned=True)
        except:
            print('Failed finding cert 2 with flag 1, looking for flag 2...')
            try:
                start = stream.readto('0x308203', bytealigned=True)
            except:
                print('Failed finding cert 2')
                sys.exit()

        stream.pos = stream.pos - 40
        cert2_size_hex = stream.read('bytes:2')
        cert2_size = int(cert2_size_hex.hex(), 16)
        cert2_bytes = stream.read('bytes:{}'.format(cert2_size))
        cert2 = writepem(cert2_bytes)
        if not check_key_valid(cert2):
            continue

        print('[*] Successfully extracted trusted certificate 2')
        return cert2

    print('[-] Failed to find the trusted cert 2')
    sys.exit()

if __name__ == "__main__":
    if len(sys.argv)!=2:
        print('vCenter_ExtraCertFromMdb.py')
        print('Modified from https://github.com/horizon3ai/vcenter_saml_login')
        print('Usage:')
        print('%s <the path of data.mdb>'%(sys.argv[0])) 
        print('Eg.')
        print('%s data.mdb'%(sys.argv[0]))      
        sys.exit(0)
    else:
        in_stream = open(sys.argv[1], 'rb')
        bin_stream = ConstBitStream(in_stream)
        idp_cert = get_idp_cert(bin_stream)
        trusted_cert_1 = get_trusted_cert1(bin_stream)
        trusted_cert_2 = get_trusted_cert2(bin_stream)
        print('[*] Extracted Trusted certificate1:')
        print(trusted_cert_1)
        print('[*] Extracted Trusted certificate2:')
        print(trusted_cert_2)
        with open("trusted_cert_1.txt", "w") as fw:
            fw.write(trusted_cert_1)
        with open("trusted_cert_2.txt", "w") as fw:
            fw.write(trusted_cert_2)










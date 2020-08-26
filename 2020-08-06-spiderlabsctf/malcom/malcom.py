from Crypto.Cipher import AES
from random import randint
from time import time
from struct import pack

BS = AES.block_size
pad = lambda s: s + '\x00' * (BS - len(s) % BS)

def randkey():
    random_number = randint(0, int(time())) & 0xFFFFFF
    key = pack('<I', random_number)
    return pad(key)

def encrypt(data, key1, key2):
    data = pad(data)

    c1 = AES.new(key1, AES.MODE_ECB)
    enc = c1.encrypt(data)

    c2 = AES.new(key2, AES.MODE_ECB)
    return c2.encrypt(enc)


secret = 'Well done! your flag is: <redacted>'
key1 = randkey()
key2 = randkey()

ct = encrypt(secret, key1, key2)

print ct.encode('hex')

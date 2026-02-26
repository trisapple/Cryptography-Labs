import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

data = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"

# always use os.urandom() to generate random bytes
key = os.urandom(32)

# pad and encrypt with ECB mode
cipher = AES.new(key, AES.MODE_ECB)
padded_data = pad(data, AES.block_size)
ct = cipher.encrypt(padded_data)

# interchange blocks 1 and 2 and decrypt
ct2 = ct[16:32] + ct[0:16] + ct[32:]
cipher = AES.new(key, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct2), AES.block_size)
print(pt)

# replay block 1 at the end of the ciphertext (before padding) and decrypt
ct3 = ct[0:64] + ct[0:16] + ct[64:]
cipher = AES.new(key, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct3), AES.block_size)
print(pt)
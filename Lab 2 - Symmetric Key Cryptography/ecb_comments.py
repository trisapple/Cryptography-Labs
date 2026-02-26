import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

data = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD" # 64 bytes

# always use os.urandom() to generate random bytes
key = os.urandom(32) # 32 bytes

# pad and encrypt with ECB mode
cipher = AES.new(key, AES.MODE_ECB)
padded_data = pad(data, AES.block_size) # AAAA...BBBB...CCCC...DDDD...\x10\x10\x10\x10
# 80 bytes, AES block size is 16 bytes
# Even if 64 is multiple of 16, padding is still added to prevent message from being mistaken for a padding value during decryption (PKCS7 standard)
# Value of each added byte is the number of bytes that are added
# \x10 is 16 in hex, so 16 bytes of \x10 are added
# \x0f is 15 in hex, so 15 bytes of \x0f are added, etc.
ct = cipher.encrypt(padded_data)
print(ct)

# interchange blocks 1 and 2 and decrypt
ct2 = ct[16:32] + ct[0:16] + ct[32:] # BBB...AAAA...CCCC...DDDD
cipher = AES.new(key, AES.MODE_ECB)
# cipher.decrypt(ct2) yields the same result as padded_data with blocks 1 and 2 swapped
pt = unpad(cipher.decrypt(ct2), AES.block_size)
print(pt)

# replay block 1 at the end of the ciphertext (before padding) and decrypt
ct3 = ct[0:64] + ct[0:16] + ct[64:] # AAA...BBBB...CCCC...DDDD...AAAA
cipher = AES.new(key, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct3), AES.block_size)
print(pt)
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

data = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"

# always use os.urandom() to generate random bytes
key = os.urandom(32)

# pad and encrypt with CBC mode - the iv is generated internally
cipher = AES.new(key, AES.MODE_CBC)
padded_data = pad(data, AES.block_size)
ct = cipher.encrypt(padded_data)

# we want to change the first 'C' of block 3 to an 'A'
# to do this, we must modify the first byte of block 2 of the ciphertext

# first, save the bytes ct object into a list (otherwise it cannot be modified)
ct2 = list(ct)

# the first byte of block 2 is at position 16
# change it by removing the 'C' and adding the 'A' (both using XOR)
ct2[16] = ct2[16] ^ ord('C') ^ ord('A')

# combine the list into a bytes object
ct2 = bytes(ct2)

# decrypt the ciphertext
# the iv is a read-only attribute of the cipher object
iv = cipher.iv

# iv must be provided for decryption - notice that block 2 is garbage
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct2), AES.block_size)
print(pt)
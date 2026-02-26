import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

data = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"

# always use os.urandom() to generate random bytes
key = os.urandom(32)

# pad and encrypt with CTR mode - the nonce is generated internally
cipher = AES.new(key, AES.MODE_CTR)
padded_data = pad(data, AES.block_size)
ct = cipher.encrypt(padded_data)

# we want to change the first 'C' of block 3 to an 'A'
# in CTR mode, we can directly XOR the ciphertext byte to flip bits in plaintext
# this only affects the specific byte, not the entire block

# first, save the bytes ct object into a list (otherwise it cannot be modified)
ct2 = list(ct)

# the first 'B' is at position 16 (start of block 2)
# change it by removing the 'B' and adding the 'A' (both using XOR)
ct2[16] = ct2[16] ^ ord('B') ^ ord('A')

# combine the list into a bytes object
ct2 = bytes(ct2)

# decrypt the ciphertext
# the nonce is a read-only attribute of the cipher object
nonce = cipher.nonce

# nonce must be provided for decryption
# notice that in CTR mode, only the targeted byte changes - no block corruption
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
pt = unpad(cipher.decrypt(ct2), AES.block_size)
print(pt)
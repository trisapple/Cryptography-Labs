import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

data = b"This is a secret message"
key = os.urandom(32)
cipher = AES.new(key, AES.MODE_CBC)
padded_data = pad(data, AES.block_size)
print(padded_data)

ct = cipher.encrypt(padded_data)

# The iv is a read - only attribute of the cipher object
iv = cipher.iv

# iv must be provided for decryption
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), AES.block_size)
print(pt)
import os
from Cryptodome.Protocol.KDF import scrypt

password = b"secret passphrase"
salt = os.urandom(16)
key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
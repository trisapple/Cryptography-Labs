import os
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA512

password = b"secret passphrase"
salt = os.urandom(16)
key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA512)

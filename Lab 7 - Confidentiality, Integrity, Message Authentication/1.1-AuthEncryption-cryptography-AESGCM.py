import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

data = b"My secret message"
aad = b"Authenticated but unencrypted data"
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)

try:
    pt = aesgcm.decrypt(nonce, ct, aad)
    print(pt)
except InvalidTag:
    print("Authentication failed!")
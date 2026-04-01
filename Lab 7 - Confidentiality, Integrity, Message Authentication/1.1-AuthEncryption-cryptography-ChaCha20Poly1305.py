import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

data = b"My secret message"
aad = b"Authenticated but unencrypted data"
key = ChaCha20Poly1305.generate_key()
chacha = ChaCha20Poly1305(key)
nonce = os.urandom(12)
ct = chacha.encrypt(nonce, data, aad)

try:
    pt = chacha.decrypt(nonce, ct, aad)
    print(pt)
except InvalidTag:
    print("Authentication failed!")
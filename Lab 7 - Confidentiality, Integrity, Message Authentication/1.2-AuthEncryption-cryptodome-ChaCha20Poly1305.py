import os
from Cryptodome.Cipher import ChaCha20_Poly1305

data = b"My secret message"
aad = b"Authenticated but unencrypted data"
key = os.urandom(32)
nonce = os.urandom(12)
cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
cipher.update(aad)
ciphertext, tag = cipher.encrypt_and_digest(data)

try:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    print(plaintext)
except (ValueError, KeyError):
    print("Authentication failed!")
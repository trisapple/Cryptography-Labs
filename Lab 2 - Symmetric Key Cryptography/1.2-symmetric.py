import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# 128 is the cipher’s block size in bits (16 bytes for AES)
padder = padding.PKCS7(128).padder()
padded_data = padder.update(b"This is a secret message") + padder.finalize() # Message is 24 bytes so 8 bytes for padding (multiple of 16)
print(padded_data)

# Always use the OS’s urandom function to generate random values
# such as keys and IVs
key = os.urandom(32) # Random 256-bit (32-byte) AES key
iv = os.urandom(16)  # Random 128-bit (16-byte) initialization vector (IV)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) # Create an AES cipher in CBC mode
encryptor = cipher.encryptor() 
ct = encryptor.update(padded_data) + encryptor.finalize() # Encrypt the padded message

decryptor = cipher.decryptor()
data = decryptor.update(ct) + decryptor.finalize() # Decrypt the padded message

unpadder = padding.PKCS7(128).unpadder()
pt = unpadder.update(data) + unpadder.finalize() # Unpad the decrypted message
print(pt)
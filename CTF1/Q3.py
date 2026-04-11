# You are given a hex-encoded ciphertext that is encrypted with 256-bit AES in ECB mode.
# The plaintext message is "Hello" and the AES key is computed from the user's password
# by applying the PBKDF2 function with a given salt and iteration count of 2048.
# The user's password is a number in the range [100000,101000].
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256

ct = bytes.fromhex("aa70f2160ce12ec527a2e5931724ca23")
salt = b"1234567812345678"

for i in range(100000,101001):
    key = PBKDF2(str(i).encode(), salt=salt, dkLen=32, count=2048, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(b"Hello", AES.block_size)
    if ct == cipher.encrypt(padded_data):
        print(i)
        break
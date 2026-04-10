# ============================== Q1 ==============================
# Compute the HMAC with SHA-512 of message "Accept" using the given hex-encoded key.
# ================================================================
from Cryptodome.Hash import HMAC, SHA512

key = bytes.fromhex("6b254e9a638e9e058983045194ea66187aceaee527e04d5e14b7e74b05d8d194")
h = HMAC.new(key, digestmod=SHA512)
h.update(b"Accept")
print(h.hexdigest())
# ============================== Q1 ==============================


# ============================== Q2 ==============================
# Generate an EC key pair for the P-256 curve and upload the corresponding public key in PEM format.
# ================================================================
from Cryptodome.PublicKey import ECC

priv = ECC.generate(curve="P-256")
pub = priv.public_key().export_key(format='PEM')
print(pub)
# ============================== Q2 ==============================


# ============================== Q3 ==============================
# You are given a hex-encoded ciphertext that is encrypted with 256-bit AES in ECB mode.
# The plaintext message is "Hello" and the AES key is computed from the user's password
# by applying the PBKDF2 function with a given salt and iteration count of 2048.
# The user's password is a number in the range [100000,101000].
# ================================================================
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
# ============================== Q3 ==============================


# ============================== Q4 ==============================
# You are given a ciphertext encrypted with the classical affine cipher.
# Given a plaintext character p, its encryption is c = (a ∙ p + b) mod 26, where the key is (a,b)
# Recover the plaintext.
# ================================================================
ct = "TPIWLGHZQ"

for a in (3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
    a_inv = pow(a, -1, 26)
    for b in range(26):
        pt = []
        for i in range(len(ct)):
            c = chr(((ord(ct[i]) - ord('A')) * a_inv - b) % 26 + ord('A'))
            pt.append(c)
        print("".join(pt))
# ============================== Q4 ==============================


# ============================== Q5 ==============================
# You are given two RSA public keys that contain a common prime factor. Compute the private key of n1.
# ================================================================
import math

n1 = 4388639816438753533533870688318164343504163222043712356459786792755487025854962182241614548071266831082675583797664153692997056068841098588334924805358207
n2 = 4459513813424634738752391287827502958105083810857827607767819796395159109430857252159972068316604454195543713431469852149209475914646976095619118019767329

p = math.gcd(n1,n2)
q = n1//p
phi = (p-1)*(q-1)
d = pow(65537,-1,phi)
print(d)
# ============================== Q5 ==============================


# ============================== Q6 ==============================
# You are given an ECDSA signature where you can predict the random vakue k used during signature generation.
# Specifically, k = SHA-256(SHA-512(message)). Recover the signer's private key.
# ================================================================
from Cryptodome.PublicKey import ECC
from Cryptodome.Hash import SHA256, SHA512

priv = ECC.generate(curve="P-256")
q = int(priv._curve.order)

message = b"My signed message"
md = SHA256.new(data=message).digest()
hm = int.from_bytes(md, "big")
r,s = 115193989780803410706606918649796393329811083160523483053757379105656478731969,113199762521833605479117318503648541949484271647409930576847236203172708176852

k = SHA512.new(data=message).digest()
k = SHA256.new(data=k).digest()
k = int.from_bytes(k, "big")

x = ((s * k - hm) * pow(r, -1, q)) % q
print(x)
# ============================== Q6 ==============================
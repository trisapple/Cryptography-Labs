from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

message = b"My secret message"

# generate RSA key
key = RSA.generate(bits=2048, e=65537)

# encrypt with public key
public_key = key.publickey()
cipher_rsa = PKCS1_OAEP.new(public_key)
ct = cipher_rsa.encrypt(message)

# decrypt with private key
cipher_rsa = PKCS1_OAEP.new(key)
pt = cipher_rsa.decrypt(ct)
print(pt)
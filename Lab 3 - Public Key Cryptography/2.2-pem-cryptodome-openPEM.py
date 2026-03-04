from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

message = b"My secret message"

# generate RSA key
key = RSA.generate(bits=2048, e=65537)

pwd = b"mypassword"
# load private key
with open("./Lab 3 - Public Key Cryptography/private.pem", "rb") as f:
    data = f.read()
    private_pem = RSA.import_key(data, passphrase=pwd)
# load public key
with open("./Lab 3 - Public Key Cryptography/public.pem", "rb") as f:
    data = f.read()
    public_pem = RSA.import_key(data)

# Import public key from PEM for encryption
cipher_rsa = PKCS1_OAEP.new(public_pem)
ct = cipher_rsa.encrypt(message)

# Import private key from PEM for decryption
cipher_rsa = PKCS1_OAEP.new(private_pem)
pt = cipher_rsa.decrypt(ct)
print(pt)
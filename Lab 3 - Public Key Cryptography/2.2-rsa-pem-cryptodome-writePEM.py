from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

message = b"My secret message"

# generate RSA key
key = RSA.generate(bits=2048, e=65537)

pwd = b"mypassword"
# serialize private key
with open("./Lab 3 - Public Key Cryptography/private.pem", "wb") as f:
    data = key.export_key(
        passphrase=pwd,
        pkcs=8,
        protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
        prot_params={'iteration_count': 131072}
    )
    f.write(data)

# serialize public key
with open("./Lab 3 - Public Key Cryptography/public.pem", "wb") as f:
    data = key.publickey().export_key()
    f.write(data)
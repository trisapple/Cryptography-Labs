from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Returns an instance of RSA Private Key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Returns an instance of RSA Public Key
public_key = private_key.public_key()

pem_pub = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pem_priv = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
)

# Write the Public Key to a file
with open("./Lab 3 - Public Key Cryptography/RSA-public.pem", "wb") as pub_file:
    pub_file.write(pem_pub)

# Write the Private Key to a file
with open("./Lab 3 - Public Key Cryptography/RSA-private.pem", "wb") as priv_file:
    priv_file.write(pem_priv)
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

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

# Load keys from PEM format
pem_public_key = serialization.load_pem_public_key(pem_pub)
pem_private_key = serialization.load_pem_private_key(
    pem_priv,
    password=b'mypassword'
)

message = b"My secret message"
ciphertext = pem_public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm = hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

plaintext = pem_private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm = hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(plaintext)

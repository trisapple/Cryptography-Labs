from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

with open("./Lab 3 - Public Key Cryptography/2.1-private.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = b'mypassword'
    )
with open("./Lab 3 - Public Key Cryptography/2.1-public.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read()
    )

message = b"My secret message"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm = hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm = hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(plaintext)

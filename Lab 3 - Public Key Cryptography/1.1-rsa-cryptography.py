from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

# Returns an instance of RSA Private Key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Returns an instance of RSA Public Key
public_key = private_key.public_key()

message = b"My secret message"
cipher_text = public_key.encrypt(
    message,
    padding.OAEP(
        mgf = padding.MGF1(algorithm = hashes.SHA256()),
        algorithm = hashes.SHA256(),
        label = None
    )
)

plaintext = private_key.decrypt(
    cipher_text,
    padding.OAEP(
        mgf = padding.MGF1(algorithm = hashes.SHA256()),
        algorithm = hashes.SHA256(),
        label = None
    )
)

print(plaintext)
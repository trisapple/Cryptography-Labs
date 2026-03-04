from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Generate key
private_key = ec.generate_private_key(ec.SECP256R1())

# Sign a message
message = b"My signed message"
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# Decode signature
r, s = decode_dss_signature(signature)
print (r, s)

# Verify a signature
public_key = private_key.public_key()
try:
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print("Signature valid")
except InvalidSignature:
    print("Signature invalid")
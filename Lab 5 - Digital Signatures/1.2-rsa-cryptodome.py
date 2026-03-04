from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

# Generate key
key = RSA.generate(bits=2048, e=65537)

# Sign a message
message = b"My signed message"
h = SHA256.new(message)
signer = pss.new(key)
signature = signer.sign(h)

# Verify a signature
public_key = key.public_key()
h = SHA256.new(message)
verifier = pss.new(public_key)
try:
    verifier.verify(h, signature)
    print("Signature valid")
except (ValueError, TypeError):
    print("Signature invalid")
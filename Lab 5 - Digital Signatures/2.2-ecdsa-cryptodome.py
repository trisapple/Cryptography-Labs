from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

# Generate key
key = ECC.generate(curve="P-256")

# Sign a message
message = b"My signed message"
h = SHA256.new(message)
signer = DSS.new(key, mode='fips-186-3', encoding='der')
signature = signer.sign(h)
print(signature)

# Verify a signature
public_key = key.public_key()
h = SHA256.new(message)
verifier = DSS.new(public_key, mode='fips-186-3', encoding='der')
try:
    verifier.verify(h, signature)
    print("Signature valid")
except ValueError:
    print("Signature invalid")
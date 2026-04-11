# Generate an EC key pair for the P-256 curve and upload the corresponding public key in PEM format.
from Cryptodome.PublicKey import ECC

priv = ECC.generate(curve="P-256")
pub = priv.public_key().export_key(format='PEM')
print(pub)
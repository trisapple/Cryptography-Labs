import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Randomly generated salt
salt = os.urandom(16)
# Derive key
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
)
key = kdf.derive(b"secret passphrase")
# Verify key
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
)
kdf.verify(b"secret passphrase", key)
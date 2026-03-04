from cryptography.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SHA256())
digest.update(b"123")
digest.update(b"456")
md = digest.finalize()
print(md.hex())
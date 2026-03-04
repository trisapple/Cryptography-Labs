from cryptography.hazmat.primitives import hashes, hmac

key = b"secret password"
h = hmac.HMAC(key, hashes.SHA256())
h.update(b"A message that must not be altered!")
signature = h.finalize()
print(signature.hex())
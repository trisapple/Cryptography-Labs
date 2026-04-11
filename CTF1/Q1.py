# Compute the HMAC with SHA-512 of message "Accept" using the given hex-encoded key.
from Cryptodome.Hash import HMAC, SHA512

key = bytes.fromhex("6b254e9a638e9e058983045194ea66187aceaee527e04d5e14b7e74b05d8d194")
h = HMAC.new(key, digestmod=SHA512)
h.update(b"Accept")
print(h.hexdigest())
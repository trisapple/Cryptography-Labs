from Cryptodome.Hash import HMAC, SHA256

key = b"secret password"
h = HMAC.new(key, digestmod=SHA256)
h.update(b"A message that must not be altered!")
print(h.hexdigest())
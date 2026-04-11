# You are given an ECDSA signature where you can predict the random vakue k used during signature generation.
# Specifically, k = SHA-256(SHA-512(message)). Recover the signer's private key.
from Cryptodome.PublicKey import ECC
from Cryptodome.Hash import SHA256, SHA512

priv = ECC.generate(curve="P-256")
q = int(priv._curve.order)

message = b"My signed message"
md = SHA256.new(data=message).digest()
hm = int.from_bytes(md, "big")
r,s = 115193989780803410706606918649796393329811083160523483053757379105656478731969,113199762521833605479117318503648541949484271647409930576847236203172708176852

k = SHA512.new(data=message).digest()
k = SHA256.new(data=k).digest()
k = int.from_bytes(k, "big")

x = ((s * k - hm) * pow(r, -1, q)) % q
print(x)
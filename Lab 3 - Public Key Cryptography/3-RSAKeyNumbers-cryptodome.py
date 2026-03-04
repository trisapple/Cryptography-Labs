from Cryptodome.PublicKey import RSA

key = RSA.generate(bits=2048, e=65537)
public_key = key.publickey()

print(f"Public exponent: {public_key.e}")
print(f"Public modulus: {public_key.n}")
print(f"Prime p: {key.p}")
print(f"Prime q: {key.q}")
print(f"Private key: {key.d}")

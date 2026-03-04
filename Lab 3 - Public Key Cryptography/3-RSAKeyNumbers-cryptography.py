from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Returns an instance of RSA Public Numbers
pub = public_key.public_numbers()
print(f"Public exponent: {pub.e}")
print(f"Public modulus: {pub.n}")

# Returns an instance of RSA Private Numbers
priv = private_key.private_numbers()
print(f"Prime p: {priv.p}")
print(f"Prime q: {priv.q}")
print(f"Private key: {priv.d}")
from Cryptodome.PublicKey import ECC
from Cryptodome.Random import random
from Cryptodome.Hash import SHA256


# Generate an ECC key -- store the private key into x
priv = ECC.generate(curve="P-256")
x = int(priv.d)

# Get the order of the key's curve
q = int(priv._curve.order)

# Get the curve's generator
G = priv._curve.G.copy()

# Get the public key and store it into H
pub = priv.public_key()
H = pub.pointQ.copy()

# Choose the message and compute its SHA256 digest
m = b"Signed message"
md = SHA256.new(data=m).digest()

# Compute ECDSA signature (r,s)
while True:
    k = random.randrange(q)
    P = k * G
    r = int(P.x) % q
    if r == 0:
        continue
    s = (r * x + int.from_bytes(md, "big")) % q
    s = (s * pow(k, -1, q)) % q
    if s == 0:
        continue
    break

# Verify the validity of the signer's public key
if H.is_point_at_infinity():
    print("Invalid public key")
    exit()
if q * H != G.point_at_infinity():
    print("Invalid public key")
    exit()

# Verify that r and s are non-zero and less than q
if r == 0 or r >= q or s == 0 or s >= q:
    print("Invalid signature")
    exit()

# Compute point R which should be equal to ppint P computed by the signer
u1 = (pow(s, -1, q) * int.from_bytes(md, "big")) % q
u2 = (r * pow(s, -1, q)) % q
R = u1 * G + u2 * H

# Verify that the x-coordinate of R is equal to r
if int(R.x) == r:
    print("Valid signature")
else:
    print("Invalid signature")

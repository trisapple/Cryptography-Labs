from Cryptodome.Random import random
from Cryptodome.PublicKey import ECC


# Method 1 to generate public/private ECC keys: manually, using hardcoded values
#####################################################################################
# Hardcode order of group (prime q)
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

# Hardcode generator G (point)
g_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
g_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = ECC.EccPoint(g_x, g_y, curve='P-256')

# Select random private key x < q
x = random.randrange(q)

# Compute public key H
H = x * G
#####################################################################################


# Method 2: use the API and access the different values (x, q, G, H) via attributes
#####################################################################################
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
#####################################################################################

# Encrypt message m1 -- ciphertext is (A1,B1)
m1 = 5
r = random.randrange(q)
A1 = r * G
B1 = (r + m1) * H

# Similarly, encrypt a second message m2 -- ciphertext is (A2,B2)
m2 = 2
r = random.randrange(q)
A2 = r * G
B2 = (r + m2) * H

# Add ciphertexts 1 and 2 -- this will produce the ciphertext of m=m1+m2
A = A1 + A2
B = B1 + B2

# Multiply ciphertext (A,B) with an integer c -- this will produce the ciphertext of c.m
c = 100
A = c * A
B = c * B

# Decrypt ciphertext (A, B) -- should output m = c.(m1+m2)
W = -(x * A) + B

# W is equal to m * H, so me must solve the DLP to retrieve m
# Here, we simply brute-force it, i.e., try all values 0, 1, 2,...
m = 0
while True:
    if m * H == W:
        break
    m = m + 1

print(m)
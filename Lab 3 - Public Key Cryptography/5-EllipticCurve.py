from Cryptodome.PublicKey import ECC

priv = ECC.generate(curve = "P-256")
pwd = b'secret password'
with open("./Lab 3 - Public Key Cryptography/ECC-private.pem", "wt") as f :
    data = priv.export_key(
        format='PEM',
        passphrase=pwd,
        protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
        prot_params={'iteration_count': 131072})
    f.write(data)
with open("./Lab 3 - Public Key Cryptography/ECC-private.pem", "rt") as f :
    data = f.read()
    priv = ECC.import_key(data, pwd)
pub = priv.public_key()

with open("./Lab 3 - Public Key Cryptography/ECC-public.pem", "wt") as f :
    data = pub.export_key(format='PEM')
    f.write(data)

with open("./Lab 3 - Public Key Cryptography/ECC-public.pem", "rt") as f :
    data = f.read()
    pub = ECC.import_key(data)

# Order of group (prime q)
q = 0xffffffff00000000ffffffffffffffffbce6faada717984f3b9cac2fc632551

# Generator G (point)
g_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
g_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = ECC.EccPoint(g_x, g_y, curve='P-256')

# Public key H (point) - copy from public key
H = pub.pointQ.copy()

# You can verify that dG == H, where d is the private key
Y = priv.d * G

# Define some points for demonstration
k = 5
S = k * G
T = (k + 1) * G

# Adding two points
R = S + T

# In-place addition
S += T

# Negating a point
R = -T

# Comparing two points
if S == T:
    print("Points are equal")
if S != T:
    print("Points are different")

# Multiplying a point by a scalar
R = k * S

# In - place multiplication by a scalar
T *= k

# Set T as point at infinity on the curve curve where T belongs
T = T.point_at_infinity()

# Check if T is the point at infinity
if T.is_point_at_infinity():
    print("T is the point at infinity")
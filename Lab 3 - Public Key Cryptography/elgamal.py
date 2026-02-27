from Cryptodome.Random import random
from Cryptodome.Util import number

# Select a random 256-bit prime q, the order of the multiplicative group (public parameter)
q = number.getPrime(256)

# With q fixed, randomly choose s until a 2048-bit prime p is found (public parameter)
while True:
    s = random.getrandbits(1792)
    p = 2*q*s + 1
    if p.bit_length() == 2048 and number.isPrime(p):
        break

# Find a generator g for the group of order q, e.g., 2^{(p-1)/q} mod p (public parameter)
g = pow(2, (p-1)//q, p)

# Select the private key x < q
x = random.randrange(q)

# Compute the public key y = g^x mod p
y = pow(g, x, p)

# Choose a small random message m (e.g., an integer)
m = 1000

# Compute ciphertext (a, b)
r = random.randrange(q)
a = pow(g, r, p)
b = pow(y, (r + m), p)

# Decrypt ciphertext (a, b)
w = (pow(a, -x, p) * b) % p

# w is equal to y^m mod p, so me must solve the DLP to retrieve m
# Here, we simply brute-force it, i.e., try all values 0, 1, 2,...
message = 0
while True:
    if pow(y, message, p) == w:
        break
    message = message + 1

print(message)
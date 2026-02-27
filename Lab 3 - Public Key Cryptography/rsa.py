from Cryptodome.Util import number

# Select two prime numbers p and q (1024 bits each)
p = number.getPrime(1024)
q = number.getPrime(1024)

# Compute public modulus n (it will be of size 1024+1024 = 2048 bits)
n = p * q

# Compute phi(n)
phi = (p-1) * (q-1)

# The public exponent e is always 65537
e = 65537

# Compute private key d as the inverse of e mod phi(n)
d = pow(e, -1, phi)

# Create the message and convert it to an integer m
message = b"Secret message"
m = int.from_bytes(message, "big")

# Encrypt the message as m^e mod n
c = pow(m, e, n)

# Decrypt the ciphertex as c^d mod n
a = pow(c, d, n)

# Convert the integer result to bytes and print it
plaintext = a.to_bytes((a.bit_length()+1) // 8, "big")
print(plaintext)
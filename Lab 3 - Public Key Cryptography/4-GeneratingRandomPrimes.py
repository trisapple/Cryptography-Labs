from Cryptodome.Random import random
from Cryptodome.Util import number

# N represents the number of bits (e.g., 1024, 2048 for RSA)
N = 1024

# q represents an upper bound for a range
q = 10**6 

# Generate a random integer r, at most N bits long
r_bits = random.getrandbits(N)

# Generate a random integer r, in the range [0, q)
r_range = random.randrange(q)

# Generate a random N-bit prime p
p = number.getPrime(N)

# Returns True if N is a prime number
is_it_prime = number.isPrime(N)

print(f"Random {N}-bit int: {r_bits}\n")
print(f"Random int < {q}: {r_range}\n")
print(f"Random {N}-bit prime: {p}\n")
print(f"Is {N} prime? {is_it_prime}")
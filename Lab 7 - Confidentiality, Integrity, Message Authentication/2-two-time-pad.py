c1 = bytes.fromhex(
    "654d1326304618fab96ec5cfeca981df63466513e16bc8fe981ed215d4c876436fc950ab87f779"
)
c2 = bytes.fromhex(
    "78441325214611e1eb73de9bb5b29bdf654c6509e67e9cad840e9104d9c9764668d503be89f97e81"
)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

xor = xor_bytes(c1, c2)

# Crib for the shorter plaintext. With a reused keystream, this reveals the
# matching prefix of the other ciphertext.
p1 = b"to be or not to be that is the question"
keystream = xor_bytes(c1, p1)
p2_prefix = xor_bytes(c2[: len(keystream)], keystream)

# The overlap is enough to recover the shared portion; the final byte of the
# longer message is inferred from the quote context.
p2 = p2_prefix + b"n"

assert xor_bytes(c1, c2[: len(c1)]) == xor_bytes(p1, p2_prefix)

print(p1.decode())
print(p2.decode())
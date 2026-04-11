# You are given a ciphertext encrypted with the classical affine cipher.
# Given a plaintext character p, its encryption is c = (a ∙ p + b) mod 26, where the key is (a,b)
# Recover the plaintext.
ct = "TPIWLGHZQ"

for a in (3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
    a_inv = pow(a, -1, 26)
    for b in range(26):
        pt = []
        for i in range(len(ct)):
            c = chr(((ord(ct[i]) - ord('A')) * a_inv - b) % 26 + ord('A'))
            pt.append(c)
        print("".join(pt))
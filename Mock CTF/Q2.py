"""
Question 2 (5 points)

Consider the following ciphertext that is encrypted with the classical Vigenere cipher under key "HKD". 
Decrypt the ciphertext and copy/paste the resulting plaintext the text box below.

Ciphertext: ZSAAIIVEU
"""

# Read ciphertext into string ct and convert to uppercase
ct = "ZSAAIIVEU"
ct = ct.upper()

length = 3
key = [7, 10, 3] # HKD

# Decrypt the ciphertext, where the i-th character is shifted by key[i%length] positions
pt = list(ct)
for i in range(len(pt)):
    pt[i] = chr((ord(pt[i]) - ord("A") - key[i%length]) % 26 + ord('A'))

# Print plaintext and key
pt = "".join(pt)
print (f"Plaintext: \n{pt}")
for i in range(length):
    key[i] = chr(key[i] + ord('A'))
key = "".join(key)
print(f"Key: {key}")

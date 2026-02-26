"""
Question 3 (5 points)

The following hex-encoded ciphertext is encrypted with AES-256 in CTR mode.

You do not know the encryption key, but you know that it encrypts the following message: Give Mallory $1000
Modify the ciphertext, so that at the recipient it decrypts as: Give Mallory $3759

Ciphertext: 6715d68b5f16bae4fba5d5c8d8db1067a8b4

Copy/paste the modified ciphertext (hex-encoded) in the text box below.
"""

# Original ciphertext (hex-encoded)
ct_hex = "6715d68b5f16bae4fba5d5c8d8db1067a8b4"

# Convert hex to bytes
ct = bytes.fromhex(ct_hex)

# Known plaintext and desired plaintext in bytes
original_plaintext = b"Give Mallory $1000"
target_plaintext = b"Give Mallory $3759"

# print(f"Original plaintext: {original_plaintext}")
# print(f"Target plaintext:   {target_plaintext}")
# print(f"Original ciphertext: {ct_hex}")
# print()

# In CTR mode, to change plaintext from P1 to P2, we XOR the ciphertext with (P1 XOR P2)
# This works because: C = P1 XOR K, so C' = C XOR P1 XOR P2 = P1 XOR K XOR P1 XOR P2 = P2 XOR K

# Original Ciphertext = Original Plaintext XORed with Keystream (C = P1 XOR K)
# Modified Ciphertext = Original Ciphertext XOR Original Plaintext XOR Target Plaintext (C' = C XOR P1 XOR P2)

# Convert ciphertext to a list so we can modify it
modified_ct = list(ct)
print(modified_ct)

# Find positions where plaintext differs and modify ciphertext
for i in range(len(original_plaintext)):
    if original_plaintext[i] != target_plaintext[i]:
        # XOR the ciphertext byte with (old_byte XOR new_byte)
        modified_ct[i] = modified_ct[i] ^ original_plaintext[i] ^ target_plaintext[i]
        # print(f"Position {i}: '{chr(original_plaintext[i])}' -> '{chr(target_plaintext[i])}'")

# Convert back to bytes and then to hex
modified_ct = bytes(modified_ct)
modified_ct_hex = modified_ct.hex()

print(f"\nModified ciphertext: {modified_ct_hex}\n")

# Verification (if we had the key and nonce, this would decrypt to target_plaintext)
print("When decrypted at the recipient, this will produce:")
print(f"{target_plaintext.decode()}")

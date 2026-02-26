"""
Question 3 (5 points)

The following hex-encoded ciphertext is encrypted with AES-256 in CTR mode.

You do not know the encryption key, but you know that it encrypts the following message: Give Mallory $1000
Modify the ciphertext, so that at the recipient it decrypts as: Give Mallory $3759

Ciphertext: 6715d68b5f16bae4fba5d5c8d8db1067a8b4

Copy/paste the modified ciphertext (hex-encoded) in the text box below.
"""

# Original and desired plaintexts
original_plaintext = "Give Mallory $1000"
desired_plaintext = "Give Mallory $3759"

# Original ciphertext in hex
ciphertext_hex = "6715d68b5f16bae4fba5d5c8d8db1067a8b4"

# Convert hex ciphertext to bytes
ciphertext = bytes.fromhex(ciphertext_hex)

# Convert plaintexts to bytes
original_pt_bytes = original_plaintext.encode('utf-8')
desired_pt_bytes = desired_plaintext.encode('utf-8')

print(f"Original plaintext: {original_plaintext}")
print(f"Original plaintext (hex): {original_pt_bytes.hex()}")
print(f"Ciphertext (hex): {ciphertext_hex}")
print(f"\nDesired plaintext: {desired_plaintext}")
print(f"Desired plaintext (hex): {desired_pt_bytes.hex()}")

# In CTR mode: Ciphertext = Plaintext XOR Keystream
# Therefore: Keystream = Plaintext XOR Ciphertext
keystream = bytes([p ^ c for p, c in zip(original_pt_bytes, ciphertext)])
print(f"\nDerived keystream (hex): {keystream.hex()}")

# To create new ciphertext: New_Ciphertext = New_Plaintext XOR Keystream
new_ciphertext = bytes([p ^ k for p, k in zip(desired_pt_bytes, keystream)])
print(f"\nNew ciphertext (hex): {new_ciphertext.hex()}")

# Verify by decrypting
verify_decrypt = bytes([c ^ k for c, k in zip(new_ciphertext, keystream)])
print(f"\nVerification - decrypted message: {verify_decrypt.decode('utf-8')}")
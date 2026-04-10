# Get ciphertext from user
ct = input("Enter ciphertext: ")
ct = ct.upper()

print("\nAll possible shift decryptions:\n")

# Print all 26 possible shifts
for key in range(26):
    pt = []
    for char in ct:
        if ('A' <= char <= 'Z'):
            # Decrypt ciphertext by subtracting key
            pt.append(chr((ord(char) - ord('A') - key) % 26 + ord('a')))
        else:
            pt.append(char)

    # Print plaintext and key
    pt_string = "".join(pt)
    k = chr(key + ord('A'))
    print(f"Key {k} (Shift {key:2}): {pt_string}")


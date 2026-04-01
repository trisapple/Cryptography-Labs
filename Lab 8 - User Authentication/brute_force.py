import base64
from Cryptodome.Protocol.KDF import scrypt

# Define the lookup table to convert between standard and cisco base64 encoding
base64chars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
cisco64chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
table = str.maketrans(cisco64chars, base64chars)

# Copy the salt from the cisco file
salt = b"Sz9isKUcavFN33"

# Convert the given cisco base64-encoded hash to bytes
# Note that standard base64-encoded strings must be a multiple of 4 bytes -- if not, pad with "=" characters
cisco_hash = "Pye28w411Wc/2byQhN3yMBQ/aPOp4qsi2Da1Vk0oP9s"
base64_hash = cisco_hash.translate(table)
padding_length = (-len(base64_hash)) % 4
base64_hash += "=" * padding_length
password_hash = base64.b64decode(base64_hash)

# Open password wordlist and iterate over the passwords -- stop when the output hash matches the given one
# The wordlist is available at: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
with open("rockyou.txt", "r") as file:
	for password in file:
		# Remove newline character at the end
		password = password.strip()
		# Make sure you use the correct parameters for scrypt
		# The encode() function converts the string password to bytes
		key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=1, p=1)
		if key == password_hash:
			print(f"Password: {password}")
			break

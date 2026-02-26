from cryptography.fernet import Fernet

key = Fernet.generate_key() # Create a random 256-bit (32 byte) encryption key, returning a 44 byte URL-safe base64-encoded key
f = Fernet(key) # Creates a Fernet cipher object f with the generated key

token = f.encrypt(b"My secret message") # Encrypted text
print(token)

pt = f.decrypt(token) # Decrypted text
print(pt)
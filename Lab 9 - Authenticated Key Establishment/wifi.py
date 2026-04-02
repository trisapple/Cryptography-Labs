import os
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import HMAC, SHA1

# Hardcode from the trace -- anonce is the AP's nonce, snonce is the client's
anonce = bytes.fromhex("0fc8136c581130fc7b7ae01c35463f0c41d27f8a172f420fc74aa021ac4ca10d")
snonce = bytes.fromhex("a0f9ee918d283ba076e71850d8a68f0b370efa1a9f4bf7afe39cb4ecc26f3f28")

# Hardcode from the trace -- aa is the AP's MAC address, sa is the client's
aa = bytes.fromhex("020000000300")
sa = bytes.fromhex("020000000000")

# The input to the PRF-512 function
message = b"Pairwise key expansion" + bytearray(1) + sa + aa + anonce + snonce + bytearray(1)

# Hardcode the MIC value from EAPOL Message 2 (trace)
mic = bytes.fromhex("d3d271caef415a1d528c34cf036ed18a")

# Hardcode the packet from EAPOL Message 2 (trace) -- make sure you zero out the MIC bytes
packet = bytes.fromhex("0103007502010a00000000000000000001a0f9ee918d283ba076e71850d8a68f0b370efa1a9f4bf7afe39cb4ecc26f3f28000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000")
        

# Open password wordlist and iterate over the passwords -- stop when the output MIC matches the given one
# The wordlist is available at: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
with open("rockyou.txt", "r") as file:
	for password in file:
		# Remove newline character at the end
		password = password.strip()
		# Make sure you use the correct parameters for pbkdf2
		# The encode() function converts the string password to bytes
		# The salt is the SSID of the AP (copy from trace)
		# Compute PMK
		pmk = PBKDF2(password.encode(), salt=b"test-wnm-rsn", dkLen=32, count=4096, hmac_hash_module=SHA1)
		# Compute the 128-bit KCK with PMK as the HMAC key
		kck = HMAC.new(pmk, msg=message, digestmod=SHA1).digest()
        
        # Compute MIC and match it (first 128 bits) against the hardcoded one -- break if match (password found)
		# Use first 128 bits of kck for the HMAC
		sig = HMAC.new(kck[:16], msg=packet, digestmod=SHA1).digest()
		if sig[:16] == mic:
			print(f"Password: {password}")
			break

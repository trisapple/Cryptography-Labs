"""
Question 1 (5 points)

Read the following declaration of integrity:
"Declaration of Integrity and Fairness by Student: I hereby declare that this ICT2213 CTF attempt is fully my own work.
If I offer help to and/or receive help from classmates, whether directly or indirectly during this CTF attempt, 
I am willing to get zero for this CTF and also to fail this module."

To accept this, encrypt the message "Accept" with AES in CBC mode, using the hex-encoded key shown below. 
Then, copy/paste the ciphertext (hex-encoded) in the following text box. 
The first part of the ciphertext should be the random 16-byte IV, followed by the actual ciphertext. 
Your answer should be a single hex-encoded value.

Key: AC0793D1FF126B103E22F298DEAC40BE
"""

import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
message = "Accept"
key = bytes.fromhex("AC0793D1FF126B103E22F298DEAC40BE")
iv = os.urandom(16)

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

result = iv + ciphertext
print(result.hex())
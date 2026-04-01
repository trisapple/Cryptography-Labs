import socket, os
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

# Load private key from file -- no password needed
with open("./Lab 8 - User Authentication/priv.pem", "rb") as key_file:
    private_key = ECC.import_key(key_file.read(), passphrase=None)

# Specify the server's IP address and TCP port number
host = "127.0.0.1"
port = 8888

# Open a socket to the server
tcpClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
tcpClient.connect((host, port))

# Receive the server's challenge (32 bytes)
nB = tcpClient.recv(32)

# Choose the client's random number (32 bytes)
nA = os.urandom(32)

# Set the server's ID, padded with 7 zero-bytes on the right
idB = b"127.0.0.1" + bytearray(7)

# Construct the message to be signed
message = nA + nB + idB

# Sign the message -- output is the binary concatenation of r and s
h = SHA256.new(message)
signer = DSS.new(private_key, mode='fips-186-3', encoding='binary')
signature = signer.sign(h)

# Send response to the server
data = nA + idB + signature
tcpClient.send(data)

# Receive and print the server's response
data = tcpClient.recv(512)
print(str(data))

# Close the socket
tcpClient.close()

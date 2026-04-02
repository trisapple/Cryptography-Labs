# Python TCP Client A
import socket, os, itertools
from Cryptodome.Hash import SHA1
from Cryptodome.Cipher import AES
from Cryptodome.Random.random import randrange

def xor_bytes(bytes1, bytes2):
    return bytes(x ^ y for x, y in zip(bytes1, bytes2))

def SHA_interleave(SS):
    i = 0
    while SS[i] == 0:
        i = i + 1
    T = SS[i:]
    if len(T) % 2 == 1:
        T = SS[i+1:]
    G = SHA1.new(data=T[::2]).digest()
    H = SHA1.new(data=T[1::2]).digest()
    K = bytes(itertools.chain(*zip(G, H)))
    return K

# DH parameters
p = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
g = 2

user = b"alice"
header = bytearray(2)

host = "127.0.0.1"  
port = 8888

tcpClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
tcpClient.connect((host, port))

# Send id
header[0] = 1
header[1] = 5
tcpClient.send(header + user)

# Receive salt
data = tcpClient.recv(2)
if data[0] != 2:
    tcpClient.close()
    exit()
l = int(data[1])
s = tcpClient.recv(l)

# Send A
a = randrange(p-1)
A = pow(g,a,p)
l = (A.bit_length()+7) // 8
mdA = int.to_bytes(A, l, "big")
header[0] = 3
header[1] = l
tcpClient.send(header + mdA)

# Receive B
data = tcpClient.recv(2)
if data[0] != 4:
    tcpClient.close()
    exit()
l = int(data[1])
mdB = tcpClient.recv(l)
B = int.from_bytes(mdB, "big")

# Compute pre-master secret S
md = SHA1.new(data=b"alice:password123").digest()
message = s + md
digest = SHA1.new(data=message).digest()
x = int.from_bytes(digest, "big")
md = SHA1.new(data=mdB).digest()
u = int.from_bytes(md[0:4], "big")
exp = (a + u * x) % (p-1)
S = pow((B-pow(g,x,p)) % p, exp, p)

# Compute session key K
SS = int.to_bytes(S, (S.bit_length()+7) // 8, "big")
K = SHA_interleave(SS)

# Compute M1
P = int.to_bytes(p, (p.bit_length()+7) // 8, "big")
G = int.to_bytes(g, (g.bit_length()+7) // 8, "big")
md1 = SHA1.new(data=P).digest()
md2 = SHA1.new(data=G).digest()
md3 = SHA1.new(data=b"alice").digest()
md = xor_bytes(md1, md2)
md = md + md3 + s + mdA + mdB + K
M1 = SHA1.new(data=md).digest()

# Send M1
header[0] = 5
header[1] = len(M1)
tcpClient.send(header + M1)

# Compute M2
message = mdA + M1 + K
M2 = SHA1.new(data=message).digest()

# Receive M2
data = tcpClient.recv(2)
if data[0] != 6:
    tcpClient.close()
    exit()
l = int(data[1])
data = tcpClient.recv(l)
if data != M2:
    tcpClient.close()
    exit()

key = K[:32]
while True:
    # Send echo request
    message = input("Enter your message here (Type 'Q' to quit): ")
    if message == "Q":
        tcpClient.close()
        exit()
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(b"echo")
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    message = nonce + tag + ciphertext
    header[0] = 7
    header[1] = len(message)
    tcpClient.send(header + message)

    # Receive echo reply
    data = tcpClient.recv(2)
    if data[0] != 8:
        tcpClient.close()
        exit()
    l = int(data[1])
    data = tcpClient.recv(l)

    # Process echo reply
    iv = data[:12]
    ct = data[12:] # first 16 bytes is the tag, remaining bytes is the ciphertext
    key = K[:32]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher.update(b"echo")
        message = cipher.decrypt_and_verify(ct[16:], ct[:16])
        print(message.decode())
    except (ValueError, KeyError):
        print("Authentication failed!")
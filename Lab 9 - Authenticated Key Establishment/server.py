import socket, os, itertools
from threading import Thread
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

s = b"Sa12lB/-1ssVAq.4"
user = b"alice"
md = SHA1.new(data=b"alice:password123").digest()
message = s + md
digest = SHA1.new(data=message).digest()
x = int.from_bytes(digest, "big")
v = pow(g, x, p)
header = bytearray(2)

# Multithreaded Python server : TCP Server Socket Thread Pool
class ClientThread(Thread): 
 
    def __init__(self,ip,port): 
        Thread.__init__(self) 
        self.ip = ip 
        self.port = port 
        print ("[+] New server socket thread started for " + ip + ":" + str(port))
 
    def run(self):
        # Check user ID
        data = conn.recv(2)
        if data[0] != 1:
            conn.close()
            return
        l = int(data[1])
        data = conn.recv(l)
        if data != user:
            conn.close()
            return

        # Send salt s
        header[0] = 2
        header[1] = 16
        conn.send(header + s)

        # Receive A
        data = conn.recv(2)
        if data[0] != 3:
            conn.close()
            return
        l = int(data[1])
        mdA = conn.recv(l)
        A = int.from_bytes(mdA, "big")

        # Send B
        b = randrange(p-1)
        B = (v + pow(g,b,p)) % p
        l = (B.bit_length()+7) // 8
        mdB = int.to_bytes(B, l, "big")
        header[0] = 4
        header[1] = l
        conn.send(header + mdB)

        # Compute pre-master secret S
        md = SHA1.new(data=int.to_bytes(B, l, "big")).digest()
        u = int.from_bytes(md[0:4], "big")
        S = pow((A*pow(v,u,p)) % p, b, p)

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

        # Receive M1
        data = conn.recv(2)
        if data[0] != 5:
            conn.close()
            return
        l = int(data[1])
        data = conn.recv(l)
        if data != M1:
            conn.close()
            return
        
        # Send M2
        message = mdA + M1 + K
        M2 = SHA1.new(data=message).digest()
        header[0] = 6
        header[1] = len(M2)
        conn.send(header + M2)

        while True:
            try:
                # Receive echo request
                data = conn.recv(2)
                if data[0] != 7:
                    conn.close()
                    return
                l = int(data[1])
                data = conn.recv(l)

                # Process echo request
                iv = data[:12]
                ct = data[12:] # first 16 bytes is the tag, remaining bytes is the ciphertext
                key = K[:32]
                try:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                    cipher.update(b"echo")
                    message = cipher.decrypt_and_verify(ct[16:], ct[:16])
                except (ValueError, KeyError):
                    message = b"Authentication failed!"
                
                # Send echo reply
                nonce = os.urandom(12)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                cipher.update(b"echo")
                ciphertext, tag = cipher.encrypt_and_digest(message)
                message = nonce + tag + ciphertext
                header[0] = 8
                header[1] = len(message)
                conn.send(header + message)
            except:
                conn.close()
                return

# Multithreaded Python server : TCP Server Socket Program Stub
TCP_IP = '0.0.0.0' 
TCP_PORT = 8888

tcpServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
tcpServer.bind((TCP_IP, TCP_PORT)) 
threads = [] 
 
while True: 
    tcpServer.listen(0) 
    print ("Multithreaded Python server : Waiting for connections from TCP clients...")
    (conn, (ip,port)) = tcpServer.accept() 
    newthread = ClientThread(ip,port) 
    newthread.start() 
    threads.append(newthread) 
 
for t in threads: 
    t.join()
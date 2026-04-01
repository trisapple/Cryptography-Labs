import socket, os
from threading import Thread
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

# Load public key from file
with open("./Lab 8 - User Authentication/pub.pem", "rb") as key_file:
    public_key = ECC.import_key(key_file.read())

# Multithreaded Python server : TCP Server Socket Thread Pool
class ClientThread(Thread): 
 
    def __init__(self,ip,port): 
        Thread.__init__(self) 
        self.ip = ip 
        self.port = port 
        print ("[+] New server socket thread started for " + ip + ":" + str(port))
 
    def run(self):
        # Send nB
        nB = os.urandom(32)
        conn.send(nB)
        # Receive nA and idB
        nA = conn.recv(32)
        idB = conn.recv(16)
        # Construct the message that the client signed
        message = nA + nB + idB
        # Receive the signature (64 bytes total, 32 per r,s)
        sig = conn.recv(64)

        # Make sure the client sent the correct value for idB
        id = b"127.0.0.1" + bytearray(7)
        if id != idB:
            conn.send(b"Server's ID does not match")
            conn.close()
            return

        # Verify the signature for the given message
        h = SHA256.new(message)
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            verifier.verify(h, sig)
            conn.send(b"Accept")
        except ValueError:
            conn.send(b"Reject")
        conn.close()

# Multithreaded Python server : TCP Server Socket Program Stub
TCP_IP = '0.0.0.0' 
TCP_PORT = 8888

tcpServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
tcpServer.bind((TCP_IP, TCP_PORT)) 
threads = [] 
 
while True: 
    tcpServer.listen() 
    print ("Multithreaded Python server : Waiting for connections from TCP clients...")
    (conn, (ip,port)) = tcpServer.accept() 
    newthread = ClientThread(ip,port) 
    newthread.start() 
    threads.append(newthread) 
 
for t in threads: 
    t.join()
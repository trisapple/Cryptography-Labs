import socket
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

def run_bob():
    # Load Alice's public key [cite: 9]
    with open("./Lab 8 - User Authentication/pub.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Setup server socket 
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 8888))
    server.listen(1)
    print("Bob is listening on port 8888...")

    conn, addr = server.accept()
    try:
        # 1. Generate and send n_b (32 bytes) 
        n_b = os.urandom(32)
        conn.sendall(n_b)

        # 2. Receive response: n_a (32), id_b (16), r (32), s (32) 
        data = conn.recv(112)
        n_a = data[:32]
        id_b_received = data[32:48]
        r = int.from_bytes(data[48:80], 'big')
        s = int.from_bytes(data[80:112], 'big')

        # 3. Verify parameters [cite: 15]
        id_b_expected = b"127.0.0.1".ljust(16, b'\x00')
        
        # 4. Reconstruct message and verify signature [cite: 19, 23]
        msg = n_a + n_b + id_b_received
        signature = utils.encode_dss_signature(r, s)

        try:
            public_key.verify(signature, msg, ec.ECDSA(hashes.SHA256()))
            if id_b_received == id_b_expected:
                conn.sendall(b"Accept")
                print("Authentication Successful: Accept")
            else:
                conn.sendall(b"Reject")
                print("Authentication Failed: ID Mismatch")
        except:
            conn.sendall(b"Reject")
            print("Authentication Failed: Invalid Signature")

    finally:
        conn.close()
        server.close()

if __name__ == "__main__":
    run_bob()
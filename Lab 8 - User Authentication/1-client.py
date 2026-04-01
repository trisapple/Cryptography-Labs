import socket
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

def run_alice():
    # Load Alice's private key [cite: 9]
    with open("./Lab 8 - User Authentication/priv.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Connect to Bob 
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 8888))

    # 1. Receive n_b (32 bytes) from Bob [cite: 18]
    n_b = client.recv(32)

    # 2. Generate n_a (32 bytes) and prepare id_b [cite: 14, 15]
    n_a = os.urandom(32)
    id_b = b"127.0.0.1".ljust(16, b'\x00')

    # 3. Sign (n_a || n_b || id_b) [cite: 19, 23]
    msg_to_sign = n_a + n_b + id_b
    signature_der = private_key.sign(msg_to_sign, ec.ECDSA(hashes.SHA256()))
    
    # Extract r and s to send as 32-byte blocks [cite: 16]
    r, s = utils.decode_dss_signature(signature_der)
    r_bytes = r.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')

    # 4. Send n_a, id_b, r, s in order 
    payload = n_a + id_b + r_bytes + s_bytes
    client.sendall(payload)

    # 5. Receive result [cite: 22]
    result = client.recv(1024)
    print(f"Server response: {result.decode()}")

    client.close()

if __name__ == "__main__":
    run_alice()
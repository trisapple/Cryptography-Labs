from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

message = b"My secret message"

# generate RSA key
key = RSA.generate(bits=2048, e=65537)

pwd = b"secret"
# serialize private key
private_pem = key.export_key(
    passphrase=pwd,
    pkcs=8,
    protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
    prot_params={'iteration_count': 131072}
)

# serialize public key
public_pem = key.publickey().export_key()

# Import public key from PEM for encryption
public_key = RSA.import_key(public_pem)
cipher_rsa = PKCS1_OAEP.new(public_key)
ct = cipher_rsa.encrypt(message)

# Import private key from PEM for decryption
private_key = RSA.import_key(private_pem, passphrase=pwd)
cipher_rsa = PKCS1_OAEP.new(private_key)
pt = cipher_rsa.decrypt(ct)
print(pt)
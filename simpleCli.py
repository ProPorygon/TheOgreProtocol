from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from base64 import b64encode, b64decode
import socket

randfile = Random.new()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 6066))
# Get servers public key
publickey = s.recv(500)
key = RSA.importKey(publickey)
message = "carl is bad"
# Pad message
pad_size = 128 - len(message) % 128
if pad_size == 0:
    pad_size = 128
message += "0" * pad_size
# Sign message
keyfile = open('private.pem', 'r').read()
cl_priv_key = RSA.importKey(keyfile)
signer = PKCS1_v1_5.new(cl_priv_key)
digest = SHA256.new()
digest.update(message)
sign = signer.sign(digest)
signature = b64encode(sign)
# Initialize AES
aes_key = randfile.read(32)
aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
ciphertext_rsa = key.encrypt(aes_key, key.publickey())
ciphertext_aes = aes_obj.encrypt(message)
print len(ciphertext_aes)
print len(signature)
# Send messages
s.send(ciphertext_rsa[0])
s.send(ciphertext_aes)
s.send(signature)
print "client sent messages"
s.close()

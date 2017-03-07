from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket

randfile = Random.new()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 6066))
publickey = s.recv(500)
key = RSA.importKey(publickey)
message = "carl is bad"
# Pad message
pad_size = 128 - len(message) % 128
if pad_size == 0:
    pad_size = 128
message += "0" * pad_size
aes_key = randfile.read(32)
aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
ciphertext_rsa = key.encrypt(aes_key, key.publickey())
ciphertext_aes = aes_obj.encrypt(message)
s.send(ciphertext_rsa[0])
s.send(ciphertext_aes)
print "client sent aes key"
s.close()

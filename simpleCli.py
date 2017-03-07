from Crypto.PublicKey import RSA
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 6066))
publickey = s.recv(500)
key = RSA.importKey(publickey)
plaintext = "carl is bad"
ciphertext = key.encrypt(plaintext, key.publickey())
s.send(ciphertext[0])
print "client sent ciphertext"
s.close()

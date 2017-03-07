from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 6066))
s.listen(1)

(clientsocket, addr) = s.accept()
key = RSA.generate(2048)
publickey = key.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1)
clientsocket.send(publickey)
ciphertext_rsa = clientsocket.recv(500)
ciphertext_aes = clientsocket.recv(1024)
aes_key = key.decrypt(ciphertext_rsa)
aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
print len(ciphertext_aes)
plaintext = aes_obj.decrypt(ciphertext_aes)
print "server got: " + plaintext + "\n"
clientsocket.close()

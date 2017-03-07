from Crypto.PublicKey import RSA
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 6066))
s.listen(1)

(clientsocket, addr) = s.accept()
key = RSA.generate(2048)
publickey = key.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1)
clientsocket.send(publickey)
ciphertext = clientsocket.recv(500)
plaintext = key.decrypt(ciphertext)
print "server got: " + plaintext + "\n"
clientsocket.close()
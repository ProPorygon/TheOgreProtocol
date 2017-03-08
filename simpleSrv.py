from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
import signatures
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 6066))
s.listen(1)

(clientsocket, addr) = s.accept()
# Generate and send public key to client
key = RSA.generate(2048)
publickey = key.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1)
clientsocket.send(publickey)
# Receives messages (using fixed size buffers until protocol is determined)
ciphertext_rsa = clientsocket.recv(500)
ciphertext_aes = clientsocket.recv(128)
signature = clientsocket.recv(344)
# Decrypt key and message
aes_key = key.decrypt(ciphertext_rsa)
aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
plaintext = aes_obj.decrypt(ciphertext_aes)
# Verify messages
cli_pub_keyfile = open("public.pem", "r").read()
verified = signatures.verify(cli_pub_keyfile, plaintext, signature)
print "server got: " + plaintext + "\nVerified: " + str(verified)
clientsocket.close()

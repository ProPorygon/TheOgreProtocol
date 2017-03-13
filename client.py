from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import socket
from signatures import sign,verify

# Connect to directory authority and get ip/port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 6066))
key = RSA.generate(2048)
publickey = key.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1)
s.send(publickey)
ciphertext_rsa = clientsocket.recv(500)
ciphertext_aes = clientsocket.recv(128)

aes_key = key.decrypt(ciphertext_rsa)
aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
plaintext = aes_obj.decrypt(ciphertext_aes)

host = plaintext.split(":")[0]
port = plaintext.split(":")[1]

# Connect to exit node located at ip/port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(publickey)
ciphertext_rsa = clientsocket.recv(500)
aes_key = key.decrypt(ciphertext_rsa)

# Send/Receive data
data = ""
next_address = ""
signature = sign(key, data)
message = next_address + data + signature
aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
ciphertext_aes = aes_obj.encrypt(message)
s.send(ciphertext_aes)

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
from signatures import sign,verify

# Set up listening server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 4321))
s.listen(1)
randfile = Random.new()

# Listen for connections
while True:
    (clientsocket, addr) = s.accept()
    # Get Client's public key
    publickey = s.recv(500)
    key = RSA.importKey(publickey)
    # Initialize AES
    aes_key = randfile.read(32)
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
    ciphertext_rsa = key.encrypt(aes_key, key.publickey())
    # Send key
    s.send(ciphertext_rsa[0])
    # Receive and unpack message
    ciphertext_aes = s.recv(256)
    message = aes_obj.decrypt(ciphertext_aes) # Remove padding
    next_addr = message[18]
    host = message.split(":")[0]
    port = message.split(":")[1] # Still need to cut off the padding at end
    data = [19,len(message)-]

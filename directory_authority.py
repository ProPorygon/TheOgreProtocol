from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
import socket
import utils

relays = {}

public_keys = {}

randfile = Random.new()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 6066))
s.listen(1)

while True:
    (clientsocket, addr) = s.accept()
    # Get client's public key (Client must first send pubkey to server)
    publickey = s.recv(500)
    key = RSA.importKey(publickey)
    message = get_relay()
    message = utils.pad_message(message)
    # Initialize AES
    aes_key = randfile.read(32)
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
    ciphertext_rsa = key.encrypt(aes_key, key.publickey())
    ciphertext_aes = aes_obj.encrypt(message)
    # Send messages
    s.send(ciphertext_rsa[0])
    s.send(ciphertext_aes)

def get_relay():
    """
    Picks relay using some yet to be determined method. Will be fully implemented later
    """
    return "127.0.0.1:5000"

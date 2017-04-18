from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import socket
import utils


DA_PORT = 4444
DA_IP = "127.0.0.1"

# Stuff with the directory authority, need to work out how this works
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DA_IP, DA_PORT))
rsa_key = RSA.generate(1024)
publickey = rsa_key.exportKey(format="OpenSSH", passphrase=None, pkcs=1)
s.send(publickey)
# Receive
aes_key_string = s.recv(128)
aes_key = AES.new(aes_key_string, AES.MODE_CBC, "0"*16)
s.recv()  # How much should this receive? All info from directory authority

# Process received route data

hoplist = []  # Replace this with processed route and key data
# Send keys and establish link
next_aes_key = AES.new(hoplist[0][1], AES.MODE_CBC, "0"*16)
next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
next_host = utils.unpackHostPort(hoplist[0][0])
next_s.connect(next_host)
wrapped_message = ""
# Generate wrapped message
for elem in hoplist:
    elem_rsa_pubkey  # have some way of getting each, probably from directory authority
    wrapped_message = utils.wrap_message(wrapped_message, elem_rsa_pubkey, elem[1])
utils.send_message_with_length_prefix(next_s, wrapped_message)

while(True):
    message = raw_input()
    for elem in hoplist:
        message = utils.add_layer(message, elem[1])
    next_s.send(message)
    utils.send_message_with_length_prefix(next_s, message)
    recieved_message = utils.recv_message_with_length_prefix(next_s)
    response = ""
    for i in reversed(range(0, len(hoplist))):
        response = utils.peel_layer(message, hoplist[i][1])
    print response

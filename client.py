from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import utils

# TODO: Change these to load from argument
DA_PORT = 4444
DA_IP = "127.0.0.1"

# TODO: Load this pub key from file
da_pub_key = ""
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DA_IP, DA_PORT))
utils.send_message_with_length_prefix(s, 'r')
# Receive
# aes_key_string = utils.recv_message_with_length_prefix(s)
# aes_key = AES.new(aes_key_string, AES.MODE_CBC, "0"*16)
data = utils.recv_message_with_length_prefix(s)  # All info from directory authority
hop_data = utils.unwrap_message(data, da_pub_key)

# Process received route data into hoplist

# hoplist format (ip, port, public_key)
hoplist = []  # Replace this with processed route and key data
# Send keys and establish link
next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
next_host = (hoplist[0][0], hoplist[0][1])
next_s.connect(next_host)
wrapped_message = ""
randfile = Random.new()
aes_key_list = []
# Generate wrapped message
for elem in hoplist:
    # have some way of getting each, probably from directory authority
    elem_aes_key = randfile.read(32)
    aes_key_list.append(elem_aes_key)
    packedroute = utils.packHostPort(elem[0], elem[1])
    wrapped_message += packedroute
    wrapped_message = utils.wrap_message(wrapped_message, elem[2], elem_aes_key)
utils.send_message_with_length_prefix(next_s, wrapped_message)

while(True):
    message = raw_input()
    for key in aes_key_list:
        message = utils.add_layer(message, key)
    next_s.send(message)
    utils.send_message_with_length_prefix(next_s, message)
    response = utils.recv_message_with_length_prefix(next_s)
    for i in reversed(range(0, len(aes_key_list))):
        response = utils.peel_layer(response, aes_key_list[i])
    print response

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
from signatures import sign,verify
import utils
import sys

if len(sys.argv) != 2:
    print "Usage: python node.py PORT_NUMBER\n"
    sys.exit(1)
# Set up listening server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', sys.argv[1]))
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
    # Instead of generating the aes key here, the client should generate it and encrypt using this relay's public key
    ciphertext_rsa = key.encrypt(aes_key, key.publickey())
    # Send key
    s.send(ciphertext_rsa[0])
    # Receive and unpack message
    ciphertext_aes = s.recv(256)
    message = aes_obj.decrypt(ciphertext_aes) # Remove padding
    next_addr = message[18]
    host = message.split(":")[0]
    port = message.split(":")[1] # Still need to cut off the padding at end
    data = [19,len(message)-e]
    # Send data to next host and port


def forwardingLoop(prevhop, nexthop, myprivkey):
    while True:
        message = utils.recv_message_with_length_prefix(prevhop)
        if message == "":
            #closing sockets may screw with other threads that use them
            prevhop.close()
            nexthop.close()
            return
        # unwrap the message or something - in spec
        message = utils.unwrap_message(message, myprivkey)
        bytessent = utils.send_message_with_length_prefix(nexthop, message)
        if bytessent == 0:
            prevhop.close()
            nexthop.close()
            return

def backwardingLoop(prevhop, nexthop, myprivkey, prevpubkey):
    while True:
        message = utils.recv_message_with_length_prefix(nexthop)
        if message == "":
            #closing sockets may screw with other threads that use them
            prevhop.close()
            nexthop.close()
            return
        # wrap the message or something - in spec
        message = utils.unwrap_message(message, myprivkey)
        message = utils.wrap_message(message, myprivkey)#don't have this function yet
        message = utils.wrap_message(message, prevkey)
        bytessent = utils.send_message_with_length_prefix(prevhop, message)
        if bytessent == 0:
            prevhop.close()
            nexthop.close()
            return

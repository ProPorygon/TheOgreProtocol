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

# Register self with directory authority, generate RSA keys

# Listen for connections
while True:
    clientsocket, addr = s.accept()
    # THREAD BOUNDARY
    # Get Client's public key
    publickey = s.recv(500)
    key = RSA.importKey(publickey)
    # need this node to have its own key pair
    routemessage = recv_message_with_length_prefix(clientsocket)
    if routemessage == "":
        #kill this thread
    aeskey, hostport, nextmessage = peelRoute(message, mykey)
    nexthost, nextport = utils.unpackHostPort(hostport)
    nexthop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nexthop.connect((nexthost, nextport))
    utils.send_message_with_length_prefix(nexthop, nextmessage)
    #spawn forwarding and backwarding threads here


def forwardingLoop(prevhop, nexthop, mykey):
    while True:
        message = utils.recv_message_with_length_prefix(prevhop)
        if message == "":
            #closing sockets may screw with other threads that use them
            prevhop.close()
            nexthop.close()
            return
        # unwrap the message or something - in spec
        message = utils.peel_layer(message, aeskey)
        bytessent = utils.send_message_with_length_prefix(nexthop, message)
        if bytessent == 0:
            prevhop.close()
            nexthop.close()
            return

def backwardingLoop(prevhop, nexthop, aeskey):
    while True:
        message = utils.recv_message_with_length_prefix(nexthop)
        if message == "":
            #closing sockets may screw with other threads that use them
            prevhop.close()
            nexthop.close()
            return
        # wrap the message or something - in spec
        message = utils.add_layer(message, aeskey)
        bytessent = utils.send_message_with_length_prefix(prevhop, message)
        if bytessent == 0:
            prevhop.close()
            nexthop.close()
            return

def peelRoute(message, mykey):
    message, aeskey = utils.unwrap_message(message, mykey)
    hostport = message[:8]
    nextmessage = message[8:]
    return (aeskey, hostport, nextmessage)
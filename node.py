from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
from signatures import sign,verify
import utils
import sys
import threading

if len(sys.argv) != 4:
    print "Usage: python node.py PORT_NUMBER DIR_AUTH_IP DIR_AUTH_PORT\n"
    sys.exit(1)

# Set up listening server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
myip = '127.0.0.1' #loopback only for now
s.bind((myip, int(sys.argv[1])))
s.listen(1)
randfile = Random.new()

# Generate RSA keys, register self with directory authority
mykey = RSA.generate(1024)
dir_auth = socket.socket(AF_INET, socket.SOCK_STREAM)
dir_auth.connect((sys.argv[2], sys.argv[3]))
result = dir_auth.send("n") #send an 'e' for exit node here, 'n' for relay node
if result == 0:
    print "The directory authority went offline during registration! Terminating relay process..."
    sys.exit(1)
result = dir_auth.sendn(mykey.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1))
if result == 0:
    print "The directory authority went offline during registration! Terminating relay process..."
dir_auth.close()

print "Successfully registered! Listening for client connections..."

#TODO replace this old code
# Listen for connections
while True:
    clientsocket, addr = s.accept()
    threading.Thread(target=startSession, args=(clientsocket)).start()

def startSession(prevhop):
    # THREAD BOUNDARY
    # Get Client's public key
    publickey = s.recv(500)
    clikey = RSA.importKey(publickey) #need this?
    # need this node to have its own key pair
    routemessage = recv_message_with_length_prefix(clientsocket)
    if routemessage == "":
        #kill this thread
        return
    aeskey, hostport, nextmessage = peelRoute(message, mykey)
    nexthost, nextport = utils.unpackHostPort(hostport)
    nexthop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nexthop.connect((nexthost, nextport))
    utils.send_message_with_length_prefix(nexthop, nextmessage)
    #spawn forwarding and backwarding threads here
    fwd = threading.Thread(target=forwardingLoop, args=(prevhop, nexthop, aeskey))
    bwd = threading.Thread(target=backwardingLoop, args=(prevhop, nexthop, aeskey))
    fwd.start()
    bwd.start()
    fwd.join()
    bwd.join()
    return


def forwardingLoop(prevhop, nexthop, aeskey):
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
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import struct
import socket
import signal
import os
import sys

def pad_message(message):
    """
    Pads a string for use with AES encryption
    :param message: string to be padded
    :return: padded message
    """
    if (len(message) % 16 != 0):
        pad_size = 16 - (len(message) % 16)
        if pad_size == 0:
            pad_size = 16
        message += chr(pad_size) * pad_size
    return message

def unpad_message(message):
    return message[:-ord(message[-1])]

def add_layer(message, aes_key):
    #TODO: modify protocol so as not to add unnecessary padding blocks
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
    ciphertext = aes_obj.encrypt(pad_message(message))
    #print "add_layer: length of ciphertext is " + str(len(ciphertext))
    return ciphertext

def peel_layer(ciphertext, aes_key):
    #print str(os.getpid()) + 'tried to unpeel\nPeeling ciphertext: ' + ciphertext
    #print "peel_layer: length of ciphertext is " + str(len(ciphertext))
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
    message = aes_obj.decrypt(ciphertext)
    return message

#uses the PUBLIC key in 'key' to encrypt
def wrap_message(message, rsa_key, aes_key):
    #generate AES key, 'k'
    #encrypt message (param 'message') with AES using 'k'
    #encrypt 'k' with RSA key (param 'key')
    #assemble final blob, then return it

    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
    ciphertext_aes = aes_obj.encrypt(pad_message(message))
    #ciphertext_rsa = rsa_key.encrypt(aes_key, rsa_key.publickey())[0]
    ciphertext_rsa = rsa_key.encrypt(aes_key, 0)[0]
    blob = ciphertext_rsa + ciphertext_aes
    return blob

def unwrap_message(blob, rsa_key):
    #seperate blob into data and encrypted AES key
    #decrypt AES key using given RSA key
    #decrypt data using the AES key
    #return the unencrypted orignal blob

    ciphertext_rsa = blob[0:128]
    ciphertext_aes = blob[128:len(blob)]
    aes_key = rsa_key.decrypt(ciphertext_rsa)
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
    message = aes_obj.decrypt(ciphertext_aes)
    message = unpad_message(message)
    #print "length of aes key: " + str(len(aes_key))
    return message, aes_key

#assumes 'message' is no longer than 4096 bytes
def send_message_with_length_prefix(tosocket, message):
    prefix = struct.pack("!I", len(message))
    bytessent = sendn(tosocket, prefix) #4 bytes, should send all of it in one go
    if bytessent == 0:
        return False
    bytessent = sendn(tosocket, message)
    if bytessent == 0:
        return False
    return True

# returns an empty string if the connection closed on the other end
def recv_message_with_length_prefix(fromsocket):
    packedlen = recvn(fromsocket, 4)
    if packedlen == "":
        return ""
    length = struct.unpack("!I", packedlen)[0]
    message = recvn(fromsocket, length)
    return message


#socket on the other end has closed if this returns 0
def sendn(tosocket, message):
    length = len(message)
    sent_so_far = 0
    while length > sent_so_far:
        bytessent = tosocket.send(message[sent_so_far:])
        if bytessent == 0:
            return 0
        sent_so_far += bytessent
    return length

def recvn(fromsocket, length):
    recv_so_far = 0
    recvbuf = ""
    while length > recv_so_far:
        newdata = fromsocket.recv(length - recv_so_far)
        bytesrecvd = len(newdata)
        if bytesrecvd == 0:
            return ""
        recvbuf += newdata
        recv_so_far += bytesrecvd
    return recvbuf

def packHostPort(ip, port):
    return socket.inet_aton(ip) + struct.pack("!i", port)

def unpackHostPort(packed):
    return (socket.inet_ntoa(packed[:4]), struct.unpack("!i", packed[4:])[0])

#hoplist is a list of tuples of the form (packedhop, RSA key object)
def packRoute(hoplist):
    message = ""
    for i in range (0, len(hoplist)):
        idx = len(hoplist) - 1 - i
        message = hoplist[idx][0] + message
        message = wrap_message(message, hoplist[idx][1])
    return message

#destination is a pre-packed hostport string
def wrap_all_messages(hoplist, destination):
    randfile = Random.new()
    wrapped_message = destination
    aes_key_list = []
    packedroute = ""
    for i in range(0, len(hoplist)):
        # have some way of getting each, probably from directory authority
        elem_aes_key = randfile.read(32)
        aes_key_list.append(elem_aes_key)
        if i != 0:
            packedroute = packHostPort(hoplist[i-1][0], hoplist[i-1][1])
        wrapped_message = packedroute + wrapped_message
        wrapped_message = wrap_message(wrapped_message, hoplist[i][2], elem_aes_key)
    return wrapped_message, aes_key_list


def add_all_layers(aes_key_list, message):
    for key in aes_key_list:
        message = add_layer(message, key)
    #print "The newly encrypted message is " + message
    return message


def peel_all_layers(aes_key_list, response):
    for i in reversed(range(0, len(aes_key_list))):
        response = peel_layer(response, aes_key_list[i])
    response = unpad_message(response)
    return response


def process_route(data):
    hoplist = []
    for a in range(3):
        rsa_key = data[8:220]
        hostport = unpackHostPort(data[:8])
        #print hostport[0]
        #print hostport[1]
        #print rsa_key
        hoplist.append((hostport[0], hostport[1], RSA.importKey(rsa_key)))
        data = data[220:]
    return hoplist

def signal_handler(received_signal, frame):
    # Do stuff
    os.killpg(os.getpgid(0), signal.SIGINT)
    sys.exit(0)
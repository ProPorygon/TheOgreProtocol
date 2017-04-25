from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import struct

def pad_message(message):
    """
    Pads a string for use with AES encryption
    :param message: string to be padded
    :return: padded message
    """
    if (len(message)%16 != 0):
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
    return ciphertext

def peel_layer(ciphertext, aes_key):
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
    ciphertext_rsa = rsa_key.encrypt(aes_key, rsa_key.publickey())[0]
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
    return message, aes_key

#assumes 'message' is no longer than 4096 bytes
def send_message_with_length_prefix(tosocket, message):
    prefix = struct.pack("!i", len(message))
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
    length = struct.unpack("!i", packedlen)
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
    return (socket.inet_ntoa(packed[:4]), struct.unpack("!i", packed[4:]))

#hoplist is a list of tuples of the form (packedhop, RSA key object)
def packRoute(hoplist):
    message = ""
    for i in range (0, len(hoplist)):
        idx = len(hoplist) - 1 - i
        message = hoplist[idx][0] + message
        message = wrap_message(message, hoplist[idx][1])
    return message

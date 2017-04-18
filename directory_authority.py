from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
import socket
import random
import utils

relay_nodes = {}

exit_nodes = {}

randfile = Random.new()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 6066))
s.listen(1)

while True:
    ##TODO Add AES/RSA Encryption, read in AD IP, port, and private key from a local file
    
    #listen for connections and serve requests:
        #Register relay nodes with IP, Port, PublicKey in NodeDict
        #Register exit nodes with IP, Port PublicKey in ExitDict
        #Provide route of N nodes and 1 exit node, with IP, Port, PublicKey for every node
    (clientsocket, addr) = s.accept()

    request_type = s.recv(1);
    if request_type == 'n': #relay node
        ip = utils.recvn(s,4)
        port = utils.recvn(s,4)
        key = utils.recvn(s,128)
        relay_nodes[(ip,port)] = key
        #send a confirmation back?

    else if request_type == 'e': #exit node
        ip = utils.recvn(s,4)
        port = utils.recvn(s,4)
        key = utils.recvn(s,128)
        exit_nodes[(ip,port)] = key;
        #send a confirmation back?

    else if request_type == 'r': #route
        num_nodes = struct.unpack("!i", utils.recvn(s,4))
        relay_list = []
        if (num_nodes > 1):
            relay_list = random_sample(relay_nodes.items(),num_nodes-1)
        exit = random.sample(exit_nodes.items(),1)
        route_message = construct_route(relay_list,exit)
        utils.sendn(s,route_message)


"""Very old stuff, kept around for reference
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
"""

def construct_route(relays,exit)
    message = ""
    for (a,b),c in relays:
        message+=(a+b+c)
    message+=(exit[0][0]+exit[0][1]+exit[1])
    return message

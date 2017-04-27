from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
import socket
import random
import utils
import sys

RSA_KEY_SIZE = 212

relay_nodes = {}

exit_nodes = {}

randfile = Random.new()

#get the DA identity from a 3-line text file
#TODO Create dir_auth_priv_key.pem
da_file = open('dir_auth_priv_key.pem','r')
da_mykey = da_file.readline()

#read in IP and Port from command line args
da_IP = "127.0.0.1"
if len(sys.argv) > 1:
    da_port = sys.argv[1]
else:
    print "No DA Port Specified!! Exiting..."
    quit()



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((da_IP, int(da_port)))
s.listen(1)

while True:
    ##TODO Add AES/RSA Encryption
    
    #listen for connections and serve requests:
        #Register relay nodes with IP, Port, PublicKey in NodeDict
        #Register exit nodes with IP, Port PublicKey in ExitDict
        #Provide route of N nodes and 1 exit node, with IP, Port, PublicKey for every node
    
    (clientsocket, addr) = s.accept()

    request_type = clientsocket.recv(1);
    if request_type == "":
        clientsocket.close()

    if request_type == 'n': #relay node
        node_addr = utils.packHostPort(addr[0],addr[1])
        key = utils.recvn(clientsocket,RSA_KEY_SIZE)
        if key == "":
            clientsocket.close()
        relay_nodes[node_addr] = key
        print "directory authority successfully registered a relay node!"

    elif request_type == 'e': #exit node
        node_addr = utils.packHostPort(addr[0],addr[1])
        key = utils.recvn(clientsocket,RSA_KEY_SIZE)
        if key == "":
            clientsocket.close()
        exit_nodes[node_addr] = key
        print "directory authority successfully registered an exit node!"

    elif request_type == 'r': #route
        num_nodes = utils.recvn(clientsocket,4)
        num_nodes = struct.unpack("!i", num_nodes)
        relay_list = []
        if (num_nodes > 1):
            relay_list = random_sample(relay_nodes.items(),num_nodes-1)
        exit = random.sample(exit_nodes.items(),1)
        route_message = construct_route(relay_list,exit)
        aes_key = randfile.read(32)
        blob = utils.wrap_message(route_message, da_mykey, aes_key)
        utils.sendn(clientsocket,blob)

    clientsocket.close()

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

def construct_route(relays,exit):
    message = ""
    for a,b in relays:
        message += a+b
    message += exit[0]+exit[1]
    return message

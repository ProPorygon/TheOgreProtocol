from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
import socket
import random
import utils
import sys

def main():
    RSA_KEY_SIZE = 212
    NUM_NODES = 3

    relay_nodes = {}

    exit_nodes = {}

    randfile = Random.new()

    #get the DA private key from a file
    da_file = open('dir_auth_priv_key.pem','r')
    da_private = da_file.read()
    da_mykey = RSA.importKey(da_private)

    #read in Port from command line args
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
        #listen for connections and serve requests:
            #Register relay nodes with IP, Port, PublicKey in NodeDict
            #Register exit nodes with IP, Port PublicKey in ExitDict
            #Provide route of N nodes and 1 exit node, with IP, Port, PublicKey for every node
        
        (clientsocket, addr) = s.accept()

        request_type = clientsocket.recv(1);
        if request_type == "":
            clientsocket.close()
            continue

        if request_type == 'n': #relay node
            msg = utils.recvn(clientsocket,RSA_KEY_SIZE+8)
            if msg == "":
                clientsocket.close()
                continue
            node_addr = msg[:8]
            key = msg[8:]
            relay_nodes[node_addr] = key
            print "directory authority successfully registered a relay node!"

        elif request_type == 'e': #exit node
            msg = utils.recvn(clientsocket,RSA_KEY_SIZE+8)
            if msg == "":
                clientsocket.close()
                continue
            node_addr = msg[:8]
            key = msg[8:]
            exit_nodes[node_addr] = key
            print "directory authority successfully registered an exit node!"

        elif request_type == 'r': #route

            #recieve encrypted aes key from client
            aes_enc = utils.recv_message_with_length_prefix(clientsocket)
            if aes_enc == "":
                clientsocket.close()
                continue
            aes_key = da_mykey.decrypt(aes_enc)
            
            relay_list = random.sample(relay_nodes.items(),NUM_NODES-1)
            exit = random.sample(exit_nodes.items(),1)
            route_message = construct_route(relay_list,exit)
            
            aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
            blob = aes_obj.encrypt(utils.pad_message(route_message))
            utils.send_message_with_length_prefix(clientsocket,blob)

        clientsocket.close()


def construct_route(relays,exit):
    message = ""
    for a,b in relays:
        message += a+b
    message += exit[0][0]+exit[0][1]
    return message


if __name__ == "__main__":
    main()

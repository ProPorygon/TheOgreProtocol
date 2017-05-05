from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import argparse
import utils
import sys
import os
from termcolor import colored


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dir_auth_ip", help="the ip address of the directory authority")
    parser.add_argument("dir_auth_port", help="the port number of the directory authority")
    parser.add_argument("destination_ip", help="the ip address of the destination")
    parser.add_argument("destination_port", help="the port number of the destination")
    args = parser.parse_args()

    DA_IP = args.dir_auth_ip
    DA_PORT = args.dir_auth_port
    DEST_HOST = args.destination_ip
    DEST_PORT = args.destination_port

    da_file = open('dir_auth_pub_key.pem', 'r')
    da_pub_key = da_file.read()
    da_pub_key = RSA.importKey(da_pub_key)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((DA_IP, int(DA_PORT)))
    s.send('r')  # specify request type (route)

    # construct and send an aes key
    randfile = Random.new()
    aes_key = randfile.read(32)
    aes_obj = aes_obj = AES.new(aes_key, AES.MODE_CBC, "0" * 16)
    aes_msg = da_pub_key.encrypt(aes_key, 0)[0]
    succ = utils.send_message_with_length_prefix(s, aes_msg)
    if not succ:
        s.close()
        print "Directory authority connection failed"
        quit()

    # Receive
    data = utils.recv_message_with_length_prefix(
        s)  # All info from directory authority
    if data == "":
        s.close()
        print "Directory authority connection failed"
        quit()

    hop_data = aes_obj.decrypt(data)

    # hoplist format (ip, port, public_key)
    # Replace this with processed route and key data
    hoplist = utils.process_route(hop_data)
    hoplist = list(reversed(hoplist))

    # Send keys and establish link
    run_client(hoplist, utils.packHostPort(DEST_HOST, int(DEST_PORT)))


def run_client(hoplist, destination):

    next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    next_host = (hoplist[len(hoplist) - 1][0], hoplist[len(hoplist) - 1][1])
    next_s.connect(next_host)
    # Generate wrapped message
    wrapped_message, aes_key_list = utils.wrap_all_messages(
        hoplist, destination)

    utils.send_message_with_length_prefix(next_s, wrapped_message)

    while True:
        print colored("CLIENT: Type some text to send through the network.", 'yellow')
        message = raw_input()
        message = utils.add_all_layers(aes_key_list, message)
        try:
            utils.send_message_with_length_prefix(next_s, message)
        except socket.error, e:
            print "client detected node closing, finished!"
            return
        try:
            response = utils.recv_message_with_length_prefix(next_s)
        except socket.error, e:
            print "client detected node closing, finished!"
            return
        response = utils.peel_all_layers(aes_key_list, response)
        print colored("CLIENT: response from server:", 'red')
        print colored(response, 'red')


if __name__ == "__main__":
    main()

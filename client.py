from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import utils
import sys
import os


def main():
    DA_IP = sys.argv[1]
    DA_PORT = sys.argv[2]
    DEST_HOST = sys.argv[3]
    DEST_PORT = sys.argv[4]

    # TODO: Load this pub key from file
    da_pub_key = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((DA_IP, DA_PORT))
    utils.send_message_with_length_prefix(s, 'r')
    # Receive
    data = utils.recv_message_with_length_prefix(
        s)  # All info from directory authority
    hop_data = utils.unwrap_message(data, da_pub_key)

    # hoplist format (ip, port, public_key)
    # Replace this with processed route and key data
    hoplist = utils.process_route(hop_data)
    # Send keys and establish link

    run_client(hoplist, utils.packHostPort(DEST_HOST, int(DEST_PORT)))


def run_client(hoplist, destination):
    print "client pid is " + str(os.getpid())
    next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    next_host = (hoplist[len(hoplist) - 1][0], hoplist[len(hoplist) - 1][1])
    next_s.connect(next_host)
    # Generate wrapped message
    wrapped_message, aes_key_list = utils.wrap_all_messages(
        hoplist, destination)
    # print "AES key list length" + str(len(aes_key_list))
    # print "hoplist length " + str(len(hoplist))
    utils.send_message_with_length_prefix(next_s, wrapped_message)
    while True:
        message = raw_input()
        message = utils.add_all_layers(aes_key_list, message)
        try:
            # TODO: check retval of this for node disconnect
            utils.send_message_with_length_prefix(next_s, message)
        except socket.error, e:
            print "client detected node closing, finished!"
            return
        try:
            response = utils.recv_message_with_length_prefix(next_s)
        except socket.error, e:
            print "client detected node closing, finished!"
            return
        if len(response) == 0:
            print "Message error occurred"
        else:
            response = utils.peel_all_layers(aes_key_list, response)
        print response


if __name__ == "__main__":
    main()

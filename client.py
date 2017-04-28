from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import utils
import sys

def main():
    DA_IP = sys.argv[1]
    DA_PORT = sys.argv[2]

    # TODO: Load this pub key from file
    da_pub_key = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((DA_IP, DA_PORT))
    utils.send_message_with_length_prefix(s, 'r')
    # Receive
    data = utils.recv_message_with_length_prefix(s)  # All info from directory authority
    hop_data = utils.unwrap_message(data, da_pub_key)

    # hoplist format (ip, port, public_key)
    hoplist = utils.process_route(hop_data)  # Replace this with processed route and key data
    # Send keys and establish link

    run_client(hoplist)


def run_client(hoplist):
    next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    next_host = (hoplist[0][0], hoplist[0][1])
    next_s.connect(next_host)
    # Generate wrapped message
    wrapped_message, aes_key_list = utils.wrap_all_messages(hoplist)
    utils.send_message_with_length_prefix(next_s, wrapped_message)

    while(True):
        message = raw_input()
        utils.add_all_layers(aes_key_list, message)
        next_s.send(message)
        utils.send_message_with_length_prefix(next_s, message)
        response = utils.recv_message_with_length_prefix(next_s)
        response = utils.peel_all_layers(aes_key_list, response)
        print response


if __name__ == "__main__":
    main()

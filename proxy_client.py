from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import utils
import sys
import os
import threading
import re
from termcolor import colored


def main():
    DA_IP = sys.argv[1]
    DA_PORT = sys.argv[2]
    CLI_ADDR = sys.argv[3]
    CLI_PORT = sys.argv[4]

# TODO: Load this pub key from file
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
    run_client(hoplist, (CLI_ADDR, int(CLI_PORT)))


def run_client(hoplist, client_host):
        # print "client pid is " + str(os.getpid())
    # print "sent the wrapped message"
    proxySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxySocket.bind(client_host)
    proxySocket.listen(10)
    while True:
        print "Waiting for Client connection on port " + str(client_host[1])
        (con_socket, con_addr) = proxySocket.accept()
        d = threading.Thread(name="Client", target=proxy_thread, args=(con_socket, con_addr, hoplist))
        d.setDaemon(True)
        d.start()


def proxy_thread(conn, client_addr, hoplist):
    print "thread launched"
    request = conn.recv(2048)
    # print request
    first_line = request.split('\n')[0]
    url = first_line.split(' ')[1]

    http_pos = url.find("://")
    if http_pos == -1:
        temp = url
    else:
        temp = url[(http_pos + 3):]

    port_pos = temp.find(":")

    webserver_pos = temp.find("/")
    if webserver_pos == -1:
        webserver_pos = len(temp)

    webserver = ""
    port = -1
    if port_pos == -1 or webserver_pos < port_pos:
        port = 80
        webserver = temp[:webserver_pos]
    else:
        port = int((temp[(port_pos + 1):])[:webserver_pos - port_pos - 1])
        webserver = temp[:port_pos]

    request = re.sub(r"http:\/\/.*?(?=\/)", "", request)

    webserver = socket.gethostbyname(webserver)
    destination = utils.packHostPort(webserver, port)
    next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    next_host = (hoplist[len(hoplist) - 1][0], hoplist[len(hoplist) - 1][1])
    next_s.connect(next_host)
    # Generate wrapped message
    wrapped_message, aes_key_list = utils.wrap_all_messages(
        hoplist, destination)
    # print "AES key list length" + str(len(aes_key_list))
    # print "hoplist length " + str(len(hoplist))
    utils.send_message_with_length_prefix(next_s, wrapped_message)

    request = utils.add_all_layers(aes_key_list, request)
    utils.send_message_with_length_prefix(next_s, request)
    data = utils.recv_message_with_length_prefix(next_s)
    conn.send(utils.peel_all_layers(aes_key_list, data))
    conn.close()

if __name__ == "__main__":
    main()

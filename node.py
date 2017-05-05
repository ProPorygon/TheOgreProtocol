from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
from signatures import sign,verify
import utils
import sys
import threading
import argparse
import signal
import os
from termcolor import colored

portstring = ""
proxy = False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exit", help="run as an exit node", action="store_true")
    parser.add_argument("--dbg", help="use public.pem and private.pem", action="store_true")
    parser.add_argument("--proxy", help="run as http proxy node", action="store_true")
    parser.add_argument("portno", type=int, help="the port this node should listen on")
    parser.add_argument("dir_auth_ip", help="the ip address of the directory authority")
    parser.add_argument("dir_auth_port", type=int, help="the port number of the directory authority")
    args = parser.parse_args()
    global proxy
    proxy = args.proxy
    # Set up listening server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    myip = '127.0.0.1' #loopback only for now
    s.bind((myip, args.portno))
    global portstring
    portstring = str(args.portno)
    s.listen(1)
    randfile = Random.new()

    # Generate RSA keys, register self with directory authority
    mykey = RSA.generate(1024)
    if args.dbg:
        f = open('private.pem', 'r')
        private = f.read()
        f.close()
        mykey = RSA.importKey(private)
    else:
        dir_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dir_auth.connect((args.dir_auth_ip, args.dir_auth_port))
        result = 0
        # send an 'e' for exit node here, 'n' for relay node
        if args.exit:
            result = dir_auth.send("e")
        else:
            result = dir_auth.send("n")
        if result == 0:
            print colored("N[" + portstring + "]: The directory authority went offline during registration! Terminating relay process...", 'cyan')
            sys.exit(1)
        msg = utils.packHostPort(myip,args.portno) + mykey.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1)
        result = utils.sendn(dir_auth, msg)
        # print result
        if result == 0:
            print colored("N[" + portstring + "]: The directory authority went offline during registration! Terminating relay process...", 'cyan')
        dir_auth.close()

    #The while condition here dictates how long the node is up
    while True:
        clientsocket, addr = s.accept()
        threading.Thread(target=startSession, args=(clientsocket, mykey, args.exit)).start()
        print colored("N[" + portstring + "]: New session started", 'cyan')

def startSession(prevhop, mykey, is_exit):
    # THREAD BOUNDARY
    # need this node to have its own key pair
    try:
        routemessage = utils.recv_message_with_length_prefix(prevhop)
    except socket.error, e:
        routemessage = ""
    if routemessage == "":
        #kill this thread
        return
    try:
        aeskey, hostport, nextmessage = peelRoute(routemessage, mykey)
    except ValueError:
        prevhop.shutdown(socket.SHUT_RDWR)
        return
    nexthost, nextport = utils.unpackHostPort(hostport)
    nexthop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nexthop.connect((nexthost, nextport))
    if nextmessage != "":
        utils.send_message_with_length_prefix(nexthop, nextmessage)
    #spawn forwarding and backwarding threads here
    fwd = threading.Thread(target=forwardingLoop, args=(prevhop, nexthop, aeskey, is_exit))
    bwd = threading.Thread(target=backwardingLoop, args=(prevhop, nexthop, aeskey, is_exit))
    fwd.start()
    bwd.start()
    fwd.join()
    bwd.join()
    return

def forwardingLoop(prevhop, nexthop, aeskey, is_exit):
    while True:
        try:
            message = utils.recv_message_with_length_prefix(prevhop)
        except socket.error, e:
            message = ""
        if message == "":
            #closing sockets may screw with other threads that use them
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return
        message = utils.peel_layer(message, aeskey)
        if is_exit:
            message = utils.unpad_message(message)
        bytessent = 0
        try:
            if (is_exit and proxy):
                bytessent = nexthop.sendall(message)
            else:
                bytessent = utils.send_message_with_length_prefix(nexthop, message)
            print colored("N[" + portstring + "]: Hopped forwards", 'cyan')
        except socket.error, e:
            pass
        if bytessent == 0:
            print colored("N[" + portstring + "]: process " + str(os.getpid()) + " closing forwardingLoop", 'cyan')
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return

def backwardingLoop(prevhop, nexthop, aeskey, is_exit):
    while True:
        message = ""
        if (is_exit and proxy):
            while True:
                data = nexthop.recv(1024)
                if len(data) > 0:
                    message += data
                else:
                    break
        else:
            try:
                message = utils.recv_message_with_length_prefix(nexthop)
            except socket.error, e:
                message = ""
        if message == "":
            #closing sockets may screw with other threads that use them
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return
        if is_exit:
            message = utils.add_layer(utils.pad_message(message), aeskey)
        else:
            message = utils.add_layer(message, aeskey)
        bytessent = 0
        try:
            bytessent = utils.send_message_with_length_prefix(prevhop, message)
            print colored("N[" + portstring + "]: Hopped backwards", 'cyan')
        except socket.error, e:
            pass
        if bytessent == 0:
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return

def peelRoute(message, mykey):
    message, aeskey = utils.unwrap_message(message, mykey)
    message = utils.unpad_message(message)
    host, port = utils.unpackHostPort(message[:8])
    hostport = message[:8]
    nextmessage = message[8:] #if nextmessage is an empty string, I'm an exit node
    return (aeskey, hostport, nextmessage)


if __name__ == "__main__":
    main()

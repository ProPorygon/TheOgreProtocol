import socket
import sys
import os
import signal
from termcolor import colored

import utils

signal.signal(signal.SIGINT, utils.signal_handler)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
myip = '127.0.0.1' #loopback only for now
s.bind((myip, int(sys.argv[1])))
s.listen(1)
print colored("Waiting for a connection...","red")
(clientsocket, addr) = s.accept()
print colored("Accepted a connection!","red")
while True:
	message = utils.recv_message_with_length_prefix(clientsocket)
	if message == "":
		sys.exit(0)
	print colored("Anonymous Message:\n" + message,'yellow')
	print colored("Please type a reponse.","red")
	revmessage = raw_input()
	if revmessage == "QUIT":
		try:
			clientsocket.shutdown(socket.SHUT_RDWR)
			s.shutdown(socket.SHUT_RDWR)
		except socket.error, e:
			pass
		sys.exit(0)
	bytessent = utils.send_message_with_length_prefix(clientsocket, revmessage)
	if bytessent == 0:
		try:
			clientsocket.shutdown(socket.SHUT_RDWR)
			s.shutdown(socket.SHUT_RDWR)
		except socket.error, e:
			pass
		print "\n\nLost connection to client. Closing...\n"
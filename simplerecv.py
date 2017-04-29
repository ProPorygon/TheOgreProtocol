import socket
import sys
import os
import signal

import utils

signal.signal(signal.SIGINT, utils.signal_handler)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
myip = '127.0.0.1' #loopback only for now
s.bind((myip, int(sys.argv[1])))
s.listen(1)

(clientsocket, addr) = s.accept()
print "server pid is " + str(os.getpid())
while True:
	message = utils.recv_message_with_length_prefix(clientsocket)
	if message == "":
		sys.exit(0)
	print "From client:\n" + message + "\n"
	print "From you:\n"
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
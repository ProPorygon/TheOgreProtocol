import socket
import sys
import os

import utils

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
myip = '127.0.0.1' #loopback only for now
s.bind((myip, int(sys.argv[1])))
s.listen(1)

(clientsocket, addr) = s.accept()
print "my pid is " + str(os.getpid())
while True:
	message = utils.recv_message_with_length_prefix(clientsocket)
	if message == "":
		sys.exit(0)
	print message
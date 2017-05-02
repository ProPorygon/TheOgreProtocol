from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import utils
import sys
import os
from termcolor import colored


def main():
    DA_IP = sys.argv[1]
    DA_PORT = sys.argv[2]
    DEST_HOST = sys.argv[3]
    DEST_PORT = sys.argv[4]

	# TODO: Load this pub key from file
	da_file = open('dir_auth_pub_key.pem','r')
	da_pub_key = da_file.read()
	da_pub_key = RSA.importKey(da_pub_key)

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((DA_IP, int(DA_PORT)))
	s.send('r') #specify request type (route)

	#construct and send an aes key
	randfile = Random.new()
	aes_key = randfile.read(32)
	aes_obj = aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
	aes_msg = da_pub_key.encrypt(aes_key,0)[0]
	succ = utils.send_message_with_length_prefix(s,aes_msg)
	if not succ:
		s.close()
		print "Directory authority connection failed"
		quit()

	# Receive
	data = utils.recv_message_with_length_prefix(s)  # All info from directory authority
	if data == "":
		s.close()
		print "Directory authority connection failed"
		quit()

	hop_data = aes_obj.decrypt(data)

	# hoplist format (ip, port, public_key)
	hoplist = utils.process_route(hop_data)  # Replace this with processed route and key data

	# Send keys and establish link
	run_client(hoplist, utils.packHostPort(DEST_HOST, int(DEST_PORT)))


def run_client(hoplist, destination):
	#print "client pid is " + str(os.getpid())
	next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	next_host = (hoplist[len(hoplist)-1][0], hoplist[len(hoplist)-1][1])
	next_s.connect(next_host)
	# Generate wrapped message
	wrapped_message, aes_key_list = utils.wrap_all_messages(hoplist, destination)
	#print "AES key list length" + str(len(aes_key_list))
	#print "hoplist length " + str(len(hoplist))
	utils.send_message_with_length_prefix(next_s, wrapped_message)
	#print "sent the wrapped message"
	while True:
		print colored("CLIENT: Type some text to send to the client.",'yellow')

		message = raw_input()
		#message = "Hi, Kevin"
		message = utils.add_all_layers(aes_key_list, message)
		try:
			utils.send_message_with_length_prefix(next_s, message) #TODO: check retval of this for node disconnect
		except socket.error, e:
			print "client detected node closing, finished!"
			return
		try:
			response = utils.recv_message_with_length_prefix(next_s)
		except socket.error, e:
			print "client detected node closing, finished!"
			return
		response = utils.peel_all_layers(aes_key_list, response)
		print colored("CLIENT: response from server:" + response,'yellow')


if __name__ == "__main__":
    main()

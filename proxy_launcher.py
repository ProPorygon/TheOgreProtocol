import sys
import subprocess
import os
import argparse
import random
import time
import signal
import utils

signal.signal(signal.SIGINT, utils.signal_handler)

num_relays = 3
num_exits = 2

parser = argparse.ArgumentParser()
#parser.add_argument("portno", type=int, help="the port a node should listen on")
parser.add_argument("dir_auth_port", type=int, help="the port number of the directory authority")
# parser.add_argument("dest_port", type=int, help="the port number of the client's destination")
parser.add_argument("cli_port", type=int, help="port number of proxy on client")
args = parser.parse_args()

os.system("python directory_authority.py " + str(args.dir_auth_port) + " &")
#wait for directory authority to spin up
time.sleep(1)

port_range = range(7000,9000)
ports = random.sample(port_range,num_relays+num_exits)
exit_port = "6666"
for port in ports[:num_relays]:
	os.system("python node.py " + str(port) + " 127.0.0.1 " + str(args.dir_auth_port) + " &")
	time.sleep(1)

for port in ports[-1*num_exits:]:
	os.system("python node.py " + str(port) + " 127.0.0.1 " + str(args.dir_auth_port) + " --exit &")
	time.sleep(1)
#subprocess.call(["python", "directory_authority.py", "7077"])
os.system("python proxy_client.py " + "127.0.0.1 " + str(args.dir_auth_port) + " 127.0.0.1 " +str(args.cli_port))#+ " &")

print "launcher done"

while True:
	pass

import sys
import subprocess
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("portno", type=int, help="the port a node should listen on")
parser.add_argument("dir_auth_port", type=int, help="the port number of the directory authority")
args = parser.parse_args()

os.system("python directory_authority.py " + str(args.dir_auth_port) + " &")
#subprocess.call(["python", "directory_authority.py", "7077"])
os.system("python node.py " + str(args.portno) + " 127.0.0.1 " + str(args.dir_auth_port) + " --exit &")

print "launcher done"

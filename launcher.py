import sys
import subprocess
import os

os.system("python directory_authority.py 7077 &")
#subprocess.call(["python", "directory_authority.py", "7077"])
os.system("python node.py 5056 127.0.0.1 7077")

print "launcher done"

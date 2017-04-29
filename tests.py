import unittest
from Crypto.PublicKey import RSA
from Crypto import Random
import utils
import node
import os
import time
import signal

import client

class TestMethods(unittest.TestCase):
    # def test_wrap_unwrap(self):
    #     rsa_key = RSA.generate(1024)
    #     input_message = "hello"
    #     wrapped_message = utils.wrap_message(input_message, rsa_key)
    #     print "Unwrapped Size: {}".format(len(input_message))
    #     print "Wrapped Size: {}".format(len(wrapped_message))
    #     result = utils.unwrap_message(wrapped_message, rsa_key)
    #     self.assertEqual(result, input_message)
    #     print ""
    #
    # def test_multi_wrap(self):
    #     rsa_key = RSA.generate(1024)
    #     input_message = "hello"
    #     wrapped1 = utils.wrap_message(input_message, rsa_key)
    #     print "First wrap size: {}".format(len(wrapped1))
    #     wrapped2 = utils.wrap_message(wrapped1, rsa_key)
    #     print "Second wrap size: {}".format(len(wrapped2))
    #     wrapped3 = utils.wrap_message(wrapped2, rsa_key)
    #     print "Third wrap size: {}".format(len(wrapped3))
    #     message = utils.unwrap_message(wrapped3, rsa_key)
    #     message = utils.unwrap_message(message, rsa_key)
    #     message = utils.unwrap_message(message, rsa_key)
    #     self.assertEqual(message, input_message)
    #     print ""

    # def test_wrap_unwrap_all(self):
    #     # Generate hoplist
    #     hoplist = []
    #     for i in range(0, 10):
    #         rsa_key = RSA.generate(1024)
    #         hoplist.append(("127.0.0.1", i, rsa_key))
    #     message, aes_key_list = utils.wrap_all_messages(hoplist, utils.packHostPort("127.0.0.1", 5569))

    #     for i in reversed(range(0, 10)):
    #         (aes_key, hostport, message) = node.peelRoute(message, hoplist[i][2])
    #         #print "round {}".format(i)
    #         unpacked = utils.unpackHostPort(hostport)
    #         #print "Host and Port: {}".format(unpacked)
    #         result = (unpacked[0], unpacked[1])
    #         self.assertTupleEqual(result, ("127.0.0.1", i))

    # def test_add_peel_all(self):
    #     randfile = Random.new()
    #     aes_key_list = []
    #     for i in range(0, 10):
    #         aes_key_list.append(randfile.read(32))
    #     message = "henlo werl"
    #     data = utils.add_all_layers(aes_key_list, message)
    #     result = utils.peel_all_layers(aes_key_list, data)
    #     self.assertEqual(result, "henlo werl")

    def test_no_dir_auth(self):
        f = open('public.pem', 'r')
        public = f.read()
        f.close()
        mykey = RSA.importKey(public)

        portno = [5266, 5267, 5268]
        hoplist = []
        dir_no_auth = 3

        #os.system("nc -l 5269 &")

        for i in range(0,len(portno)):
            hoplist.append(("127.0.0.1", portno[i], mykey))
            os.system("python node.py " + str(portno[i]) + " 127.0.0.1 " + str(dir_no_auth) + " --exit --dbg &")
            time.sleep(1)
        client.run_client(hoplist, utils.packHostPort("127.0.0.1", 5269))

if __name__ == "__main__":
    signal.signal(signal.SIGINT, utils.signal_handler)
    unittest.main()
    os.killpg(os.getpgid(0), signal.SIGINT)

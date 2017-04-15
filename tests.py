import unittest
from Crypto.PublicKey import RSA
import utils

class TestMethods(unittest.TestCase):
    def test_wrap_unwrap(self):
        rsa_key = RSA.generate(1024)
        input_message = "hello"
        wrapped_message = utils.wrap_message(input_message, rsa_key)
        print "Unwrapped Size: {}".format(len(input_message))
        print "Wrapped Size: {}".format(len(wrapped_message))
        result = utils.unwrap_message(wrapped_message, rsa_key)
        self.assertEqual(result, input_message)
        print ""

    def test_multi_wrap(self):
        rsa_key = RSA.generate(1024)
        input_message = "hello"
        wrapped1 = utils.wrap_message(input_message, rsa_key)
        print "First wrap size: {}".format(len(wrapped1))
        wrapped2 = utils.wrap_message(wrapped1, rsa_key)
        print "Second wrap size: {}".format(len(wrapped2))
        wrapped3 = utils.wrap_message(wrapped2, rsa_key)
        print "Third wrap size: {}".format(len(wrapped3))
        message = utils.unwrap_message(wrapped3, rsa_key)
        message = utils.unwrap_message(message, rsa_key)
        message = utils.unwrap_message(message, rsa_key)
        self.assertEqual(message, input_message)
        print ""


if __name__ == "__main__":
    unittest.main()

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

def pad_message(message):
    """
    Pads a string for use with AES encryption
    :param message: string to be padded
    :return: padded message
    """
    pad_size = 128 - len(message) % 128
    if pad_size == 0:
        pad_size = 128
    message += "0" * pad_size
    return message

def wrap_message(message, key):
    #generate AES key, 'k'
    #encrypt message (param 'message') with AES using 'k'
    #encrypt 'k' with RSA key (param 'key')
    #assemble final blob, then return it
    randfile = Random.new()
    aes_key = randfile.read(32)
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
    ciphertext_aes = aes_obj.encrypt(pad_message(message))
    rsa_key = RSA.importKey(key)
    ciphertext_rsa = rsa_key.encrypt(aes_key)
    blob = ciphertext_rsa + ciphertext_aes
    return blob

def unwrap_message(blob, key):
    #seperate blob into data and encrypted AES key
    #decrypt AES key using given RSA key
    #decrypt data using the AES key
    #return the unencrypted orignal blob
    ciphertext_rsa = blob[0,255]
    ciphertext_aes = blob[256,len(blob)-1]
    rsa_key = RSA.importKey(key)
    aes_key = rsa_key.decrypt(ciphertext_rsa)
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0"*16)
    message = aes_obj.decrypt(ciphertext_aes)
    return message

def route_unwrap(blob, key):
    packed = unwrap_message(blob, key)
    return packed[0,21],packed[22,len(blob)-1]

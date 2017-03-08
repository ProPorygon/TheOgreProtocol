from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode

def verify(pub_key_string, message, signature):
    """
    Verifies a message, given a signature
    :param pub_key_string: string containing public key message sender
    :param message: message that was sent
    :param signature: base64 encoded signature given by sender
    :return: boolean inidicating success of verification
    """
    pub_key = RSA.importKey(pub_key_string)
    signer = PKCS1_v1_5.new(pub_key)
    digest = SHA256.new()
    digest.update(message)
    verified = signer.verify(digest, b64decode(signature))
    return verified

def sign(priv_key_string, message):
    """
    Generate a signature, given a string
    :param priv_key_string: string containing sender private key
    :param message: message to be sent and signed
    :return: base64 encoded signature
    """
    priv_key = RSA.importKey(priv_key_string)
    signer = PKCS1_v1_5.new(priv_key)
    digest = SHA256.new()
    digest.update(message)
    sign = signer.sign(digest)
    signature = b64encode(sign)
    return signature

from Crypto.PublicKey import RSA

key = RSA.generate(2048)

plaintext = "hi, i'm a dog :)"

public_key = key.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1)

ciphertext = key.encrypt(plaintext, key.publickey())#cipher_rsa.encrypt(plaintext)
print ciphertext
print key.decrypt(ciphertext)
print len(public_key)
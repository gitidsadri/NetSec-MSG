import socket
import select


import socket
import select
#!/usr/bin/python3

from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64

from Crypto.Cipher import PKCS1_OAEP
import binascii

import base64
import sys
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

import hmac
import hashlib


import random
import string
from Crypto.Cipher import AES
############################################

#!/bin/usr/env python
import socket
import ssl
import pprint

import socket
import sys
import time

#server

PrivKey = b'key.pem'
certserver = b'cert.pem'
HOST = '127.0.0.1'
PORT = 1234

iv=0
Skey=0
w, h = 5, 10;
ivSkey = [[0 for x in range(w)] for y in range(h)] 
#ivSkey([0,iv,Skey]
#ivSkey = np.zeros((10,3))
NumClient = 0 # number of client
###############################################################@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
############Encryp AES
def encAES(key, iv, Msg):
	#key = bytes(key, 'utf-8')
	#iv = bytes(iv, 'utf-8')
	enc_s = AES.new(key.encode(), AES.MODE_CFB, iv.encode())
	cipher_text = enc_s.encrypt(Msg)#BYTE MSA
	encoded_cipher_text = base64.b64encode(cipher_text)
	return encoded_cipher_text
############
#############DECRYP AES
def decAES(key, iv, cipher_text):
	decryption_suite = AES.new(key.encode(), AES.MODE_CFB, iv.encode())
	plain_text = decryption_suite.decrypt(base64.b64decode(cipher_text))
	#print(plain_text.decode('utf-8').strip())
	return plain_text.decode('utf-8').strip()
############

######################Get PublicKey from cert.pem; conert to der filr
def encrypMsg(msg,certserver):
    pem = open(certserver).read()
    #lines = pem.replace(" ",'').split()
    #der = a2b_base64(''.join(lines[1:-1]))
    # ; Extract RSA key
    #cert = DerSequence()
    #cert.decode(der)
    #tbsCertificate = DerSequence()
    #tbsCertificate.decode(cert[0])
    #subjectPublicKeyInfo = tbsCertificate[6]
    rsa_key = RSA.importKey(pem)
    #print('priv key: ',rsa_key)
    # create a cipher via PKCS1.5
    cipher = PKCS1_v1_5.new(rsa_key)
    #print('privkey of encription: ',cipher)
    # encrypt
    cipher_text = cipher.encrypt(msg)
    # do base64 encode
    cipher_text = base64.b64encode(cipher_text)
    #print('Enmsa utf8:' ,cipher_text.decode('utf-8'))
    return cipher_text
############################################################

#################################Get privateKey from key.pem; dec with key.pem
def decrypMsg(msgEn,cert):
	private_key_string = open(cert,"r").read()
	private_key = RSA.importKey(private_key_string)
	Privcipher = PKCS1_v1_5.new(private_key)
	# decode base64
	msgEn = base64.b64decode(msgEn)
	# decrypt
	plain_text = Privcipher.decrypt(msgEn, None)
	#print(plain_text.decode('utf-8').strip())
	return plain_text
################################################
###################################hmac
def HMAC(data, key):
    ###key = b'123'  # Defined as a simple string.
    key = bytes(key, 'utf-8')
    data = bytes(data, 'utf-8')  # Assumes `data` is also a string.
    return hmac.new(key, data, hashlib.sha256).hexdigest()

#print(HMAC(b'i am priyamL'))
#########################
#################sign
def sign(Ms4sign, PrivKey):
	from Crypto.Signature import PKCS1_v1_5
	#Ms4sign = b'This message is from me.'
	Ms4sign = bytes(Ms4sign, 'utf-8')
	with open(PrivKey, 'r') as f:
    		key = RSA.importKey(f.read())
	Mshash = SHA256.new(Ms4sign)
	signer = PKCS1_v1_5.new(key)
	signature = signer.sign(Mshash)
	return signature
###########################
###########################VERIFY sigature
def verifysign(signature, certserver, Ms4sign):
    from Crypto.Signature import PKCS1_v1_5
    with open(certserver, 'rb') as f:
        key = RSA.importKey(f.read())
    Mshash = SHA256.new(Ms4sign)
    verifier = PKCS1_v1_5.new(key)
    if verifier.verify(Mshash, signature):
        signOk = 'ok'
    else:
        print('No sign')
        signOk = 'no'
        connection.close()
###################################

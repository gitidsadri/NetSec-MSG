import socket
import select
import errno

##############@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
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

import hmac
import hashlib

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


import os
from math import floor
import random
import string
from Crypto.Cipher import AES
############################
import socket
import ssl
import pprint

import socket
import sys
import secrets
import time

PrivKey = b'key.pem'
certclient = b'cert.pem'
HOST = '127.0.0.1'
PORT = 1234

# array save msg and number
w, h = 2, 100;#  deliver & msgnum
MsgsNo = [[0 for x in range(w)] for y in range(h)] 

#################Genrate session key=AES
Skey = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))
iv = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))
##################
MsgNumber=0
############Encryp AES
def encAES(Skey, iv, Msg):
	enc_s = AES.new(Skey.encode(), AES.MODE_CFB, iv.encode())
	cipher_text = enc_s.encrypt(Msg)#BYTE MSA
	encoded_cipher_text = base64.b64encode(cipher_text)
	return encoded_cipher_text
############
#############DECRYP AES
def decAES(Skey, iv, cipher_text):
	decryption_suite = AES.new(Skey.encode(), AES.MODE_CFB, iv.encode())
	plain_text = decryption_suite.decrypt(base64.b64decode(cipher_text))
	return plain_text.decode('utf-8').strip()
############
'''
######################Get PublicKey from cert.pem; conert to der filr
def encrypMsg(msg,certserver):
    #msg = bytes(msg, 'utf-8')
    pem = open(certserver).read()
    lines = pem.replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))
    # ; Extract RSA key
    cert = DerSequence()
    cert.decode(der)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]
    rsa_key = RSA.importKey(subjectPublicKeyInfo)
    print(rsa_key)
    # create a cipher via PKCS1.5
    cipher = PKCS1_v1_5.new(rsa_key)
    # encrypt
    cipher_text = cipher.encrypt(msg)
    # do base64 encode
    cipher_text = base64.b64encode(cipher_text)
    #print(cipher_text.decode('utf-8'))
    return cipher_text
############################################################
'''

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
"""
#################################Get privateKey from key.pem; dec with key.pem
def decrypMsg(msg,certserver):
    private_key_string = open("key.pem","r").read()
    private_key = RSA.importKey(private_key_string)
    Privcipher = PKCS1_v1_5.new(private_key)
    # decode base64
    cipher_text = base64.b64decode(cipher_text)
    # decrypt
    plain_text = Privcipher.decrypt(cipher_text, None)
    print(plain_text.decode('utf-8').strip())
    return plain_text
#######################################
"""
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

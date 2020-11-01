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
###########################
###########################VERIFY sigature
def verifysign(signature, certserver, Ms4sign):
	from Crypto.Signature import PKCS1_v1_5
	with open(certserver, 'rb') as f:
    		key = RSA.importKey(f.read())
	Mshash = SHA256.new(Ms4sign)
	verifier = PKCS1_v1_5.new(key)
	if verifier.verify(Mshash, signature):
    		signOk='ok'
	else:
    		print('There is a problem with your authentication!')
    		signOk='no'
    		connection.close()
###############################################################################################################################
def auth(sock):
	#print('iv000000>>>', iv)
	message = 'SALAM_ASL' + str(iv)
	#cert = b'client.pem'
	    #print >>sys.stderr, 'sending "%s"' % message
	#sock.sendall(message)
	###1
	sock.send(message.encode())
	###

	###2
	#print("cli")
	temp=str(sock.recv(1024).decode())
	lenth= len(temp)
	certserver=temp[9:lenth+9]
	certserver=bytes(certserver, 'utf-8')
	#print(certserver)
	###

	###3
	sock.send(certclient)

	###

	###4
	OK = sock.recv(1024)
	#print(OK)
	###

	#######5
	###############Genrate nonce & add lenth
	nonce=secrets.randbits(32)
	nonce=str(nonce)
	orgnonce = nonce #withat lenth
	if(len(nonce) < 10):
		nonce = str(0) +str(len(nonce)) + nonce
	else:
		nonce = str(len(nonce)) + nonce

	#add nonce to skey
	SK_noce = nonce + Skey
	##
	#print(SK_noce)

	#SK_noce = bytes(SK_noce, 'utf-8')
	cipher_text = encrypMsg(SK_noce.encode(),certclient)
	##
	##sgin(hmac)
	#print('Skey')
	#print(Skey)
	#print('nonce')
	#print(orgnonce)
	mac = HMAC(Skey, orgnonce)
	sig = sign(mac, PrivKey)
	#print(sig)
	#print(mac)
	##

	##send SessionMg
	sock.send(cipher_text)
	sock.send(sig)
	##
	##############

	###6
	#resive sessionkeyOk
	SKok = sock.recv(1024)
	#
	########3verify server
	#decode
	#signatureServer=decrypMsg(SKok,PrivKey)
	#
	#print('verifysign')
	#print(signatureServer)
	#print(orgnonce)
	verifysign(SKok, certserver, orgnonce.encode())
	####6

	###7
	sock.send(b'lets talk!')
	###
	OK = sock.recv(1024)

################################################################################################################################
##############@@@@@@@@@@@@@@@@@@@@@@@@@@@

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 4287
my_username = input("Username: ")

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
client_socket.connect((IP, PORT))

# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
######client_socket.setblocking(False)

##########@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
auth(client_socket)
############@@@@@@@@@@@@@@@@@@@


# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)


################Messaging
while True:

    GetMsgs = input("Press Enter to chat ")# elam amadegi baraye chat & if there was msg from others get it
    EncMsg=encAES(Skey, iv, b'*get')
    client_socket.send(EncMsg)
    EnrecMsg = client_socket.recv(1024).decode() #recive if there was
    PlainrecMsg = decAES(Skey, iv, EnrecMsg)
    if PlainrecMsg != "no"and PlainrecMsg[:4] != "dely": #  there was msg from others
	    #print("ggg",Skey,iv)
	    lenId= int(PlainrecMsg[:1])
	    SorId = PlainrecMsg[1:lenId+1] # get source id
	    PlainrecMsg = PlainrecMsg[lenId+1:] # msg for  destination id
            ##get msgNum
	    num = int(PlainrecMsg[int(len(PlainrecMsg)) - 2 :])
	    msgNum =  PlainrecMsg[int(len(PlainrecMsg)) - 2 - num :int(len(PlainrecMsg)) - 2]
            ##
            ##get only msg
	    msg =  PlainrecMsg[:int(len(PlainrecMsg)) - 2 - num]
            ##
	    print(f'<{SorId}> said: ',msg)
	    msgNumok = "*ok" + msgNum #to say server that you recive msg with the msgNum
	    EncMsg=encAES(Skey, iv, msgNumok.encode('utf-8'))
	    client_socket.send(EncMsg)
    if PlainrecMsg[:4] == "dely":
       print('deliverd: ',PlainrecMsg[4:])

    Msg = input("enter msg: ")
    ToId = input("enter User Id: ")
    Msg = Msg.encode('utf-8')
    ToId = ToId.encode('utf-8')
###add number & id to the end of msg
    LenIdMsg= 1 + int(len(username))+int(len(str(MsgNumber))) # lengh of id+ MsgNumber + 1(lengh of "/")
    if LenIdMsg < 10:
       LenIdMsg= "0" + str(LenIdMsg)
    Msg = str(len(ToId)).encode('utf-8') + ToId + Msg + username + b'/' + str(MsgNumber).encode('utf-8') + str(LenIdMsg).encode('utf-8')  
###
    #if MsgNumber < 99:#save msg number
       #MsgsNo[1][MsgNumber]=MsgNumber
    MsgNumber = MsgNumber + 1#  number of next mgs
    EncMsg=encAES(Skey, iv, Msg)  ##Msg.encode()
    #message_header = f"{len(EncMsg):<{HEADER_LENGTH}}".encode('utf-8')#####
    client_socket.send(EncMsg)

    #DesGotMsg = client_socket.recv(1024).decode() #msg fail or ok
    #print(DesGotMsg)

    ####EnrecMsg = client_socket.recv(1024).decode() #recive reply
    #if EnrecMsg != "ok": #msg tayid ke khodash migirad ramz nist 
    
    #decMsg = decMsg(sock.recv())
    #if(Msg == "end." or Msg == ".."):
        #break
#client_socket.close()


"""
while True:

    # Wait for user to input a message
    message = input(f'{my_username} > ')

    # If message is not empty - send it
    if message:

        # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
        message = message.encode('utf-8')
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header + message)

    try:
        # Now we want to loop over received messages (there might be more than one) and print them
        while True:

            # Receive our "header" containing username length, it's size is defined and constant
            username_header = client_socket.recv(HEADER_LENGTH)

            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(username_header):
                print('Connection closed by the server')
                sys.exit()

            # Convert header to int value
            username_length = int(username_header.decode('utf-8').strip())

            # Receive and decode username
            username = client_socket.recv(username_length).decode('utf-8')

            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            message = client_socket.recv(message_length).decode('utf-8')

            # Print message
            print(f'{username} > {message}')

    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            sys.exit()

        # We just did not receive anything
        continue

    except Exception as e:
        # Any other exception - something happened, exit
        print('Reading error: '.format(str(e)))
        sys.exit()
"""

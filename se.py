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
######################################################################################################################
def auth(connection):
            #############1
            # get iv
            temp = str(connection.recv(1024).decode())
            lenth = len(temp)
            global iv
            global Skey
            iv = temp[9:lenth + 9]

            #print('iv>>>', iv)
            ###

            ###2
            HiSendCert = b'SALAM_ASL' + certserver
            connection.send(HiSendCert)
            #print("sercrt",HiSendCert)
            ###

            ###3
            certclient = connection.recv(1024)
            ###

            ####4
            connection.send(b'ok')

            #####

            #######5
            # RECIVE>>>>>>>>>>>SessionMg
            Clcipher_text = connection.recv(1024)
            ##decSession 4 sign&mac
            SK_noce = decrypMsg(Clcipher_text, PrivKey)
            ##seprate nonce & skey
            SK_noce = str(SK_noce.decode())
            #print(SK_noce)
            lenth = int(SK_noce[0:2])
            exnonce = SK_noce[2:lenth + 2]
            exSkey = SK_noce[lenth + 2:len(SK_noce)]
            Skey = exSkey
            # print(exnonce)
            # print(exSkey)
            # print(SK_noce)
            ####

            ##recive signatura
            signature = connection.recv(1024)
            #print(signature)
            ##
            ##check sgin(hmac)
            #print('exSkey')
            #print(exSkey)
            #print('exnonce')
            #print(exnonce)
            Ms4sign = HMAC(exSkey, exnonce)
            Ms4sign = bytes(Ms4sign, 'utf-8')
            #print(Ms4sign)
            # signature = bytes(signature, 'utf-8')
            #print('verifysign')
            #print(signature)
            #print(Ms4sign)
            verifysign(signature, certserver, Ms4sign)
            # print(len(sig))
	    ##

            ###6
            # send SessionKey ok
            signNonce = sign(exnonce, PrivKey)

            
            #print(signNonce)
            # SKok=encrypMsg(signNonce,certclient)
            connection.send(signNonce)
            ###

            ###7
            if  (connection.recv(1024).decode()) == "lets talk!":
            #print(connection.recv(1024).decode())
               connection.send(b'ok')
            ###
            
##############################################################################

################recive secret messaging
def resmsg(connection, iv, Skey):
	    #while True:
		    #print(iv,"  " , Skey)
		    #sendData = input("enter msg: ")
		    ##Encdata=encMsg(sendData,KeyEnc)
		    ##connection.send(Encdata)
		    EncMsgCl = connection.recv(1024).decode()
		    #global iv
		    #global Skey
		    return decAES(Skey, iv, EncMsgCl)
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
		    #return EncMsgCl
		    #if(DecMsgCl == "end." or DecMsgCl == ".."):
		                #break
	    #connection.close()
##############################################################@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 4287

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# SO_ - socket option
# SOL_ - socket option level
# Sets REUSEADDR (as a socket option) to 1 on socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind, so server informs operating system that it's going to use given IP and port
# For a server using 0.0.0.0 means to listen on all available interfaces, useful to connect locally to 127.0.0.1 and remotely to LAN interface IP
server_socket.bind((IP, PORT))

# This makes server listen to new connections
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# List of connected clients - socket as a key, user header and name as data
clients = {}

print(f'Listening for connections on {IP}:{PORT}...')

# Handles message receiving
def receive_message(client_socket):

    try:

        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())

        # Return an object of message header and message data
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:

        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False

while True:

    # Calls Unix select() system call or Windows select() WinSock call with three parameters:
    #   - rlist - sockets to be monitored for incoming data
    #   - wlist - sockets for data to be send to (checks if for example buffers are not full and socket is ready to send some data)
    #   - xlist - sockets to be monitored for exceptions (we want to monitor all sockets for errors, so we can use rlist)
    # Returns lists:
    #   - reading - sockets we received some data on (that way we don't have to check sockets manually)
    #   - writing - sockets ready for data to be send thru them
    #   - errors  - sockets with some exceptions
    # This is a blocking call, code execution will "wait" here and "get" notified in case any action should be taken
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)


    # Iterate over notified sockets
    for notified_socket in read_sockets:

        # If notified socket is a server socket - new connection, accept it
        if notified_socket == server_socket:

            # Accept new connection
            # That gives us new socket - client socket, connected to this given client only, it's unique for that client
            # The other returned object is ip/port set
            client_socket, client_address = server_socket.accept()
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
            auth(client_socket)
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#####################################################################################################
            # Client should send his name right away, receive it
            user = receive_message(client_socket)

            # If False - client disconnected before he sent his name
            if user is False:
                continue

            # Add accepted socket to select.select() list
            sockets_list.append(client_socket)

            # Also save username and username header
            clients[client_socket] = user
            #print('3')
            print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))

            ###############save iv & add & Skey
            #print("NumClient ",NumClient)
            Id = (user["data"].decode("utf-8"))
            ivSkey[NumClient][0] = Id
            ivSkey[NumClient][1] = iv
            ivSkey[NumClient][2] = Skey
            NumClient = NumClient + 1
            #print(ivSkey)
            #print(ivSkey[0][2])

            #if Id == "mehdi":
               #ivSkey[2][0] = 234

            #####
            #print(clients[client_socket])
        # Else existing socket is sending a message
        else:
#########@@@@@@@@@@@@@@@@@@@@@@@@@
            user = clients[notified_socket]
            Id = (user["data"].decode("utf-8"))
            for i in range(10): # which client , for his key & iv
                if Id == ivSkey[i][0]:
                    e = i
            #print("org addres: ",client_address[1] , " add in array: " ,ivSkey[e][0], " key: " ,ivSkey[e][2])
            message = notified_socket.recv(1024).decode()
            message= decAES(ivSkey[e][2], ivSkey[e][1], message)
            if message == "*get": # if its for get msg
               #print("id for send *get & ivSkey[e][3]", Id, " " , ivSkey[e][3])
               if ivSkey[e][3] == 0: # az ghabl payam nadard
                  if ivSkey[e][4] != 0: #deliver shode
                     dely="dely".encode("utf-8") + ivSkey[e][4].encode("utf-8")
                     dely= encAES(ivSkey[e][2], ivSkey[e][1], dely)
                     notified_socket.send(dely)
                     ivSkey[e][4]=0
                  #print("send Noooooooo id for send *get & ivSkey[e][3]  client_socket", Id, " " , ivSkey[e][3]," " ,client_socket)
                  else:
                     dely="no".encode("utf-8")
                     dely= encAES(ivSkey[e][2], ivSkey[e][1], dely)
                     notified_socket.send(dely)# u dont have msg

               else:ivSkey[e][3] = 0 #payam dari ve ghablan ersal shode begir
            
            ####notified_socket.send(b"ok") ######## aval be khodash javab bedahad ke gir nakonad
            #message != "*get": # if his msg is not for others

            if message[:3] == "*ok":#see a msg deliverd!
               #print("EEEEEEEEEE " ,message[int(len(message)) - 2:int(len(message)) - 1])
               if message[int(len(message)) - 2:int(len(message)) - 1] == "/":
                  #print("222222222222222 " ,message[3:int(len(message)) - 2])
                  MsgNoOk = message[3:int(len(message)) - 2]
                  MsgNoint = message[int(len(message)) - 1:] # khode shomare
               else:
                  MsgNoOk = message[3:int(len(message)) - 3]
                  MsgNoint = message[int(len(message)) - 2:]# khode shomare
               for client_socket in clients:
                   ##print(clients[client_socket]['data'].decode('utf-8'))
                   if clients[client_socket]['data'].decode('utf-8') == MsgNoOk:
                       ##print(client_socket)
                       for i in range(10): # get his key
                          if MsgNoOk == ivSkey[i][0]: 
                             e = i
                             ivSkey[e][4] = MsgNoint # bit of delivery of msnomber
                       ##print(DesId,ivSkey[e][2] , ivSkey[e][1])
                       #print("3333333333333333 " ,client_socket)
                       #client_socket.send(b" recived!")


            if message != "*get" and message[:3] != "*ok":
               lenId= int(message[:1])
               DesId = message[1:lenId+1] # destination id
               DesMsg = message[lenId+1:] # msg for  destination id

               #MsgNumber = message[int(len(message)) - 1 :] # 
               #MsgNumber = message[int(len(message)) - 1 - int(MsgNumber) :int(len(message)) - 1] # 
               #MsgNumber = MsgNumber + Id.encode('utf-8') # add his id ti msgnum

               ### add source id
               DesMsg = DesMsg.encode('utf-8')
               FromId = Id.encode('utf-8')
               DesMsg = str(len(FromId)).encode('utf-8') + FromId + DesMsg ########example" 5mehdisalam
               ####
               #print("id & des & source: ",Id," ", DesId, "  " , FromId)
               for client_socket in clients:
                   ##print(clients[client_socket]['data'].decode('utf-8'))
                   if clients[client_socket]['data'].decode('utf-8') == DesId:
                       ##print(client_socket)
                       for i in range(10): # get his key
                          if DesId == ivSkey[i][0]: 
                             e = i
                       ##print(DesId,ivSkey[e][2] , ivSkey[e][1])
                       Ensdmsg= encAES(ivSkey[e][2], ivSkey[e][1], DesMsg)#msg for destination
                       ivSkey[e][3] = 1
                       client_socket.send(Ensdmsg)
            

            add = client_address[1]
            #break
######@@@@@@@@@@@@@@@@@@@@@@@@@@@

            # Receive message
            #message = receive_message(notified_socket)

            # If False, client disconnected, cleanup
            if message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))

                # Remove from list for socket.socket()
                sockets_list.remove(notified_socket)

                # Remove from our list of users
                del clients[notified_socket]

                continue

            # Get user by notified socket, so we will know who sent the message
            user = clients[notified_socket]
            #print(user["data"].decode("utf-8"))
            #print(f'<{user["data"].decode("utf-8")}> says: ',message )
            #####
            #print(clients[client_socket])
            #print(clients[notified_socket])
            #print(notified_socket)
            #print(client_socket)
#if clients[notified_socket]['data'] == "mehdi":
#   
            #notified_socket.send(b"999")

"""
            # Iterate over connected clients and broadcast message
            for client_socket in clients:

                # But don't sent it to sender
                if client_socket != notified_socket:

                    # Send user and message (both with their headers)
                    # We are reusing here message header sent by sender, and saved username header send by user when he connected
                    client_socket.send(user['header'] + user['data'] + message['header'] + message['data'])

    # It's not really necessary to have this, but will handle some socket exceptions just in case
"""

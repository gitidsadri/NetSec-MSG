# NetSec-MSG
Implement a simple secure messenger;
The goal of this project is to design a secure messenger program consisting of two main parts; the server and the client. The encription protocol used in this system is a new and simple protocol called ASL like SSL protocol. This protocol consists of two phases of handshaking and data exchange session.
A) handshaking phase: In this phase, the two parties after identifying each other, agree on the key and the encryption protocol. The process for this protocol is shown in the picture.
Description:
 "EncpubS" means public key server encryption. The rest of the naming is the same.
 Messages are single-line, except for certificates.
 After each message a blank line (equivalent to the two characters \n) will be sent.
 Certificates are sent in the form of a PEM text file.
 Encrypted messages will be sent as Base64.
 All certificates are signed by a CA so that they can be validated on both sides.
B) Message exchange session phase:
After sharing the key and specifying the encryption algorithm, we enter the message exchange phase where all messages
Submissions are sent securely (confidentially and verified). The communication protocol in this phase is as follows:
The client will have the following commands:
− REGISTER [USERID]
− MESSAGE [MESSAGEID] [USERID] [MESSAGE]
− MESSAGE [MESSAGEID] [{USERID1,USERID2…}] [MESSAGE]
In response to each of these commands, the server sends the message [OK] MESSAGEID or [FAILED [MESSAGEID
The server can also send the following command (when receiving a message from a client and sending it to the target client)
− MESSAGE [MESSAGEID] [FROMUSERID] [MESSAGE]
The client sends the message [OK] MESSAGEID or [FAILED] MESSAGEID to the server.
All of the above commands must:
- MESSAGEID is a unique identifier. (To confirm sending or receiving messages)
- USERID contains a maximum of 111 letters and contains only English letters and numbers.
- MESSAGE converted to Base64 message (with a maximum length of 11111 characters)
- Similar to the delivery phase, a blank line will be sent after each message.

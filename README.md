Chatroom‑Based P2P File Transfer Application

Overview

This is a secure, decentralized command‑line chat and file‑sharing application.  
   Client–Server  for chatroom discovery and membership  
   Peer‑to‑Peer (P2P)  for all text & file exchanges  
   End‑to‑End Encryption :  
 	 RSA for key exchange  
 	 AES‑CFB for fast payload encryption  

Features

1.  Chatroom Management (server side)   
     /createroom <name>  
     /listrooms  
     /joinroom <room_id>  
     /leaveroom <room_id>  
     /listmembers <room_id>

2.  P2P in Current Room (client side)   
     /msg <client > <message>  
     /broadcast <message>  
     /sendfile <client > <filename>  
     /sendfilegroup <filename>

3.  Security   
     RSA keypair per client (PEM files)  
     Server RSA‑encrypts a single AES key+IV per room  
     All messages & files AES‑encrypted in transit  

Prerequisites

OS:  Linux or WSL2  
Compiler:  gcc with  pthread support  
Libraries:   
  OpenSSL (libssl dev, libcrypto dev)  
Tools:  make, tar/unzip

   
Directory Structure

ChatRoomFileTransfer/
├── include/
│ └── common.h
├── src/
│ ├── main.c
│ ├── server.c
│ ├── client.c
│ ├── p2p.c
│ └── encryption.c
├── Makefile
└── README.md


 include/common.h  
  Shared constants, `ClientInfo` and `Chatroom` definitions.  
 src/main.c  
  Mode selector: server vs. client.  
 src/server.c  
  Chatroom & key‑exchange server logic.  
 src/client.c  
  CLI, RSA handshake, AES decryption, P2P orchestration.  
 src/p2p.c  
  P2P send/receive of encrypted messages & files.  
 src/encryption.c  
  RSA & AES helper functions.  


Build Instructions

1. Unpack the project:
   unzip ChatRoomFileTransfer.zip
   cd ChatRoomFileTransfer

2. Create build directory and compile:
	mkdir -p build
	make

Usage

1. Start the server

./build/chatapp
Enter 1 as Server
Server started on port 8888...

2. Start clients (in separate terminals) with different port in same machine or different Ips

./build/chatapp
Select mode:
2. Client
Client 1 connecting...
Client 1 ready> 

3. Chatroom Commands (from client prompt)

> /listrooms
> /createroom MyRoom
> /listrooms
> /joinroom 1
> /listmembers 1

4. P2P Messaging & File Transfer

> /msg 2 Hello, peer!
> /broadcast Hello everyone in MyRoom!
> /sendfile 2 testfile.txt
> /sendfilegroup announcement.pdf



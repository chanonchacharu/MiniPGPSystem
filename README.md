# DES332 Mini Project: PGPSystem

In this mini project, our group aims to create a Python program to illustrate our knowledge on algorithms related to encryption and decryption messages over a network by using a PGP-like system as a reference. Our project must satisfy the following criteria: cryptographic and applications requirement. We will implement a system that utilizes RSA public key algorithms for key generation, encryption, and decryption to uphold the authenticity standards. Additionally, we choose AES algorithm for symmetric key implementation to deal with confidentiality. The session key generation and key exchange is done using Diffie-Hellman Key Exchange protocol. The project will show the step-by-step process of the whole system from inputting the message to recipient receiving the final message via an interface.

# Files and Setup

utility.py : Utility functions necessary for RSA, DH, and PGP system operations
RSA.py : RSA Algorithm implementation with Encryption and Decryption functions
DH.py : Diffie-Hellman Key Exchange Protocol for shared secret session key generation
PGPSystem.py : Main program to run the PGP-like System

Installed this following package:

    pip install pycryptodome

# Testing the Program

1. Download all the files
2. Run PGPSystem.py on preferred Python IDE
3. Once the program run, user will be prompted with an interface to select some options.
4. Create new user by typing "1" into the prompt. Choose the username and press "Enter". In this example, a new user "Lisa" has been created. The program display her Private Key (PK) and Public Key (PU). In real setting, these information should be kept secret; however, for education purposes, we show them.
5. There must be at least TWO users in the system to enable the sending message functionality. Hence, create another user by repeating Step 4.
6. After creating at least two users, type "2" to select the sending message option. Choose the sender by typing in the username. Choose the receiver by typing in the username.
7. Type any message into the prompt. The interface will show a confirmed message if the message is successfully send.
8. If user would like to check message history, type "3". Then type the username. Consequently, the program will display the previous messages between two users (this also include the case where the user send the message to him/herself)
9. To exit the program, type "q".

# Group Members

**1. Pauruetai Kobsahai 6322770064**

- Resource provider

**2. Chanon Charuchinda 6322770692**

- Algorithm Design and Code implementation

**3. Suthisa Panto 6322773985**

- Public Speaker, Presentation and Report

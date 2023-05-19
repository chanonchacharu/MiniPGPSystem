from utility import ByteToBinary, HexadecimalToBinary, BinaryToHexadecimal, BinaryToByte
from RSA import RSAAlgorithm, KeyGenerator
from DH import DiffieHellmanConnection
from Crypto.Util import number
from Crypto.Cipher import AES
import hashlib

'''
Menu Options:

Create new users (alice, bob, jane, etc.)
Send Message (select sender and receiver)
View Message History (select one of the user)
Quit the program (press "q" to exit the program)

All message are at runtime, so nothing will be saved 

'''
numOfBit = 16

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = self.hashPassword(password)
        self.publicKey, self.privateKey = KeyGenerator(numOfBit).generate_key()
        self.messageHistory = []
    
    def hashPassword(self, password):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(password.encode('utf-8'))
        hashed_password = sha256_hash.hexdigest()
        return hashed_password

    def display_key(self):
        print(f"User: {self.username}\nPU: {self.publicKey}\nPK: {self.privateKey}")

class Message:
    def __init__(self, sender, recipient, content):
        self.sender = sender
        self.recipient = recipient
        self.content = content
        
    def __repr__(self):
        return f"{self.sender} -> {self.recipient}: {self.content}"

class PGPSystem:
    def __init__(self):
        self.users = {}
        self.sessionKeyStorage = {}
    
    def add_user(self, name, password):
        if name in self.users.keys():
            print("Username already exist! Choose a new one.")
        else:
            self.users[name] = User(name, password)
            # Display username and password (incase the users forgot)
            print(f"User {name}, Password: {password} has been created\n")
            self.users[name].display_key()
    
    def userVerification(self, username, password):
        # Compute the hashed password
        sha256_hash = hashlib.sha256()
        sha256_hash.update(password.encode('utf-8'))
        hashed_password = sha256_hash.hexdigest()
        # Check if the hashed password are the same or not
        if username not in self.users.keys(): return False
        return self.users[username].password == hashed_password

    def establishedDHSession(self, sender_name, receiver_name):
        # Check if the session between two user has already been created
        userpairkey = sender_name+";;"+receiver_name
        reversed_userpairkey = receiver_name+";;"+sender_name

        if userpairkey not in self.sessionKeyStorage.keys() and reversed_userpairkey not in self.sessionKeyStorage.keys():
            public_prime = number.getPrime(16)
            public_generator = None
            for g in range(2, public_prime):
                if pow(g, (public_prime - 1) // 2, public_prime) != 1 and pow(g, public_prime - 1, public_prime) == 1:
                    public_generator = g

            # Generate random prime numbers as private prime for sender and reciever
            sender_private = number.getPrime(16)
            receiver_private = number.getPrime(16)

            sender_dhc = DiffieHellmanConnection(public_generator, public_prime, sender_private)
            receiver_dhc = DiffieHellmanConnection(public_generator, public_prime, receiver_private)

            sender_SSSK = sender_dhc.compute_shared_secret_key(receiver_dhc.public_key)
            _ = receiver_dhc.compute_shared_secret_key(sender_dhc.public_key)
            num_bytes = (sender_SSSK.bit_length() + 7) // 8

            hash_object = hashlib.sha256(sender_SSSK.to_bytes(num_bytes, byteorder='big'))
            hash_bytes = hash_object.digest()
            sessionKey =  hash_bytes 

            self.sessionKeyStorage[userpairkey] = sessionKey
            self.sessionKeyStorage[reversed_userpairkey] = sessionKey
        
        return self.sessionKeyStorage[userpairkey]

    def send_message(self, sender_name, receiver_name, plaintext):
        # Retried the Sender and Receiver
        if sender_name not in self.users.keys() or receiver_name not in self.users.keys():
            print("Invlaid username...")
            return
        sender = self.users[sender_name]
        receiver = self.users[receiver_name]

        # Get Shared Secret Session Key using DH Protocol
        sessionKey =  self.establishedDHSession(sender_name, receiver_name)

        #--------------------- Encryption ----------------------#
        cipher = AES.new(sessionKey, AES.MODE_EAX)
        # Encrypt the message m using session key SSSK: {m}_SSSK
        ciphertext, digest = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        nonce = cipher.nonce

        binaryCiphertext = ByteToBinary(ciphertext)
    
        binaryNonce = ByteToBinary(nonce)
        binaryDigest = ByteToBinary(digest)

        # Compute {hash-sha1(m)}_PRsender
        hashedMessage = hashlib.sha1(plaintext.encode("utf-8")).hexdigest()

        # Alice send message to Bob
        privateKeySender = sender.privateKey # d, n
        binaryHashedMessage = HexadecimalToBinary(hashedMessage)

        rsa = RSAAlgorithm()
        digitalSignature = rsa.RSAEncryption(binaryHashedMessage, privateKeySender)
        hexDigitalSignature = BinaryToHexadecimal(digitalSignature)

        # Constructed the signed message: M || {hash-sha1(M)}_PR_S
        signature_length = str(len(digitalSignature))
        signedMessage = hexDigitalSignature + "||" + signature_length

        # This part still missing: {hash-sha1(m)}_PRsender || len({hash-sha1(m)}_PRsender)
        completeMessage = binaryCiphertext +";"+ signedMessage +";" + binaryNonce + ";" + binaryDigest
        # Show the encrypted message structure (for educational purposes)
        print(f"\nEncrypted Message: {completeMessage}\n")

        #-----------------------Decrypt Plaintext message------------------------#
        # Decrypt for the plaintext message
        receivedEncryptedMessage = completeMessage.split(";")

        ByteReceiverMessage = BinaryToByte(receivedEncryptedMessage[0])
        ByteDigest = BinaryToByte(receivedEncryptedMessage[-1])

    
        receiver_cipher = AES.new(sessionKey, AES.MODE_EAX, nonce = BinaryToByte(receivedEncryptedMessage[2]))
        BytedecryptMessage = receiver_cipher.decrypt_and_verify(ByteReceiverMessage, ByteDigest)
        plaintextMessage = BytedecryptMessage.decode('utf-8')

        #-------------------------Decryption Process--------------------------#
        received_signature, signature_length = receivedEncryptedMessage[1].split("||")

        publicSenderKey = sender.publicKey 
        # binary_received_signature = HexadecimalToBinary(received_signature) # should be equal to digitalSignature
        binary_received_signature = format(int(received_signature, 16), '0' + str(int(signature_length) * 4) + 'b')

        decryptedDigitalSignature = rsa.RSADecryption(binary_received_signature, publicSenderKey)

        hexDecryptedDigitalSignature = BinaryToHexadecimal(decryptedDigitalSignature)

        # Compute the hash of the received message
        receivedhashedMessage = hashlib.sha1(plaintextMessage.encode("utf-8")).hexdigest()

        if receivedhashedMessage == hexDecryptedDigitalSignature:
            print("Successful! The digital signature is valid.")
            print(f"Message sent from {sender.username} to {receiver.username}")
            # Create a message object and add it into messageHistory of Sender and Receiver
            message = Message(sender.username, receiver.username, plaintextMessage + " {SSSK: " + str(sessionKey) + "}")
            sender.messageHistory.append(message)
            receiver.messageHistory.append(message)
        else:
            print("The digital signature is invalid.")

    def view_message_history(self, username):
        if username not in self.users.keys():
            print(f"Error: {username} not found in the system")
            return 
        
        user = self.users[username]

        if len(user.messageHistory) == 0:
            print(f"No messages for user {username}")
        else:
            print(f"Message history of user {username}")
            for message in user.messageHistory:
                print(message)
    
    def run_interface(self):
        print("Welcome to PGPSystem!")
        while True:
            print("\nOptions:")
            print("1. Create new user")
            print("2. Send message")
            print("3. View message history")
            print("q. Quit the program")

            choice = input("Select an option: ")

            if choice == "1":
                name = input("Enter new username: ")
                password = input("Enter password: ")
                self.add_user(name, password)

            elif choice == "2":
                # Check if there is any user or not
                if len(self.users.keys()) == 0:
                    print("No users in the system yet!\n")
                elif len(self.users.keys()) < 2:
                    print("Only have one user. Please add another user")
                else:
                    # Display available list of 
                    print("This is the list of users in the system:")
                    for idx, user in enumerate(self.users.keys()):
                        print(f"{idx+1}: {user}")
                    print()

                    # Adding sending message options: one users or multiple users
                    print("Message Options:\n1.Single Recipient\n2.Multiple Recipient\n")
                    messageOptions = input("Enter message options: ")

                    def validateUsersExistance(user_list):
                        for username in user_list:
                            if username not in self.users.keys():
                                return False
                        return True

                    if messageOptions == "1":
                        sender_name = input("Enter sender name: ")                            
                        recipient_name = input("Enter recipient name: ")
        
                        if validateUsersExistance([sender_name, recipient_name]):
                            # Sender verification process
                            senderPassword = input("Enter password: ")
                            isVerifiedSender = self.userVerification(sender_name, senderPassword)

                            if isVerifiedSender:
                                print("Password Authenticate Successfully.\n")
                                chatroomEnded = False
                                while chatroomEnded != True:
                                    content = input("Enter message content: ")
                                    self.send_message(sender_name, recipient_name, content)
                                    # Check if the user would like to end the message
                                    checkStatus = input("Send more messages (Y/N): ")
                                    if checkStatus.lower() == "y":
                                        continue 
                                    else:
                                        chatroomEnded = True
                            else:
                                print("Invalid Password. Not authorized to send message. ")
                            
                        else:
                            print("Invalid username(s)...")

                    elif messageOptions == "2":
                        sender_name = input("Enter sender name: ")
                        askRecipeint = True
                        recipient_list = []
                        while askRecipeint != False:
                            recipient_name = input("Enter recipient name: ")
                            recipient_list.append(recipient_name)
                            isMoreReceiver = input("Any more recipients (y/n): ")
                            if isMoreReceiver.lower() == "y":
                                continue
                            else:
                                askRecipeint = False
                        
                        user_list = [sender_name] + recipient_list
                        if validateUsersExistance(user_list):
                            # Sender verification process
                            senderPassword = input("Enter password: ")
                            isVerifiedSender = self.userVerification(sender_name, senderPassword)

                            if isVerifiedSender:
                                print("Password Authenticate Successfully.\n")
                                chatroomEnded = False
                                while chatroomEnded != True:
                                    content = input("Enter message content: ")
                                    for recipient_name in recipient_list:
                                        self.send_message(sender_name, recipient_name, content)
                                    # Check if the user would like to end the message
                                    checkStatus = input("Send more messages (Y/N): ")
                                    if checkStatus.lower() == "y":
                                        continue 
                                    else:
                                        chatroomEnded = True
                            else:
                                print("Invalid Password. Not authorized to send message. ")

                            
                        else:
                            print("Invalid username(s)...")          

                    else:
                        print("Wrong Message Options. Please try again later")
                
            elif choice == "3":
                # Check if there is any user or not
                if len(self.users.keys()) == 0:
                    print("No users in the system yet!\n")
                elif len(self.users.keys()) == 0:
                    print("Only have one user. Please add another user")
                else:
                    # Display available list of 
                    print("This is the list of users in the system:")
                    for idx, user in enumerate(self.users.keys()):
                        print(f"{idx+1}: {user}")
                    print()
                    user_name = input("Enter username to see message history: ")
                    user_password = input("Enter password: ")
                    isVerifiedUser = self.userVerification(user_name, user_password)

                    if isVerifiedUser:
                        self.view_message_history(user_name)
                    else:
                        print("Incorrect Pass. Cannot granted the request to see message history")
            
            elif choice == "q":
                print()
                print("-"*45)
                print("Thank you for using our PGP system")
                print("-"*45)
                break
                
            else:
                print("Invalid option")
            
            print("-"*45)

if __name__ == "__main__":
    pgpsystem = PGPSystem()
    pgpsystem.run_interface()
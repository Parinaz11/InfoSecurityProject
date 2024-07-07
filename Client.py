import json
import socket
import threading
import base64

from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

HOST = 'localhost'
PORT = 12345
P2P_PORT = 12346
peer_public_key = None
group_member_pk = dict()  # port:publicKey, port2:publicKey2, ...

class Client:
    def __init__(self):
        global peer_public_key
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))
        self.username = None
        # Generate RSA key pair
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey().export_key()

        self.access_level = 1  # Access level to build a group
        self.groups_member_ports = dict()

    def run(self):
        try:
            while True:
                print("1. Register")
                print("2. Login")
                print("3. Exit")
                print("4. Private Chat")
                print("5. Group Chats")
                if self.access_level == 1:
                    print("6. Create Group Chat")

                choice = input("Enter your choice: ")

                if choice == "1":
                    self.register_user()
                elif choice == "2":
                    self.login_user()
                elif choice == "3":
                    print("Exiting...")
                    break
                elif choice == "4":
                    self.private_chat()
                elif choice == "5":
                    self.enter_group_chat()
                elif choice == "6" and self.access_level == 1:
                    self.create_group_chat()
                else:
                    print("Invalid choice!")

        except Exception as e:
            print("Client exception:", str(e))

    def send_message(self, message):
        self.socket.sendall(message.encode())

    def receive_message(self):
        return self.socket.recv(1024).decode()

    def register_user(self):
        self.send_message("register")
        email = input("Enter your email: ")
        self.send_message(email)
        username = input("Enter your username: ")
        self.send_message(username)
        password = input("Enter your password: ")
        self.send_message(password)
        confirm_password = input("Confirm your password: ")
        self.send_message(confirm_password)
        # Send public key
        self.send_message(self.public_key.decode())

        print(self.receive_message())

    def login_user(self):
        global P2P_PORT

        self.send_message("login")
        self.username = input("Enter your username: ")
        self.send_message(self.username)
        password = input("Enter your password: ")
        self.send_message(password)
        # Get the p2p port number which is unique
        response = self.receive_message()
        print(response)
        if response == "Login failed!":
            return
        P2P_PORT = int(self.receive_message())
        p2p_thread = threading.Thread(target=start_p2p_server, daemon=True)
        p2p_thread.start()
        # self.send_message(str(P2P_PORT))

    def enter_group_chat(self):

        self.send_message("EnterGroups")
        print("--- Your Groups ---")
        # self.send_message(self.username)
        try:
            # Receive the JSON-encoded groups dictionary
            groups_json = self.socket.recv(4096).decode('utf-8')
            # Deserialize the JSON string to a dictionary
            groups = json.loads(groups_json)
        except (json.JSONDecodeError, KeyError):
            print("Failed to decode groups data")
            return

        if not groups:
            print("No groups found")
            return

        for group, details in groups.items():
            print(f'{group} (access level {details[0]})')

        group_name = input("Enter the group name: ")

        if group_name not in groups:
            print("Group does not exist")
            return

        print("1. Enter group")
        access_level = groups[group_name][0]

        if access_level == 1:
            print("2. Add to group")
            print("3. Modify user access levels")

        try:
            command = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid input")
            return

        self.send_message(str(command))

        if command == 1:
            global group_member_pk
            group_member_pk = dict()
            # Send the port number to the server to get the group port number and connect
            print(f"Entered group {group_name}")
            self.send_message(group_name)
            group_port = int(self.receive_message())
            print("Received group port", group_port)
            address = 'localhost'
            # admin: Getting this group's user ports from server so that every message is sent to others

            # if access_level == 1:
            #     member_ports_str = self.receive_message()
            #     pk_temp = self.receive_message()  # in format port1:pk1,port2:pk2,...
            #     pk_temp2 = dict()
            #     self.groups_member_ports[group_name] = set(map(int, member_ports_str.split(",")))
            #     print("Member Ports:", self.groups_member_ports[group_name])
            #     # switch to the correct format
            #     pk_temp2[group_name] = list(map(str, pk_temp.split(",")))
            #     for port_key_pair in pk_temp2:
            if access_level == 1:
                member_ports_str = self.receive_message()
                pk_temp = self.receive_message()  # in format port1:pk1,port2:pk2,...

                pk_temp2 = dict()
                self.groups_member_ports[group_name] = set(map(int, member_ports_str.split(",")))
                print("Member Ports:", self.groups_member_ports[group_name])
                print("Received PK Temp:", pk_temp)

                # switch to the correct format
                pk_list = list(map(str, pk_temp.split(",")))
                print("PK List:", pk_list)

                pk_temp2[group_name] = pk_list
                for port_key_pair in pk_list:
                    temp_port_num = port_key_pair.split(":")[0]
                    temp_key_pem = port_key_pair.split(":")[1]
                    # print("Member with port", temp_port_num , "has key", temp_key_pem)
                    group_member_pk[temp_port_num] = temp_key_pem.encode()

            # Receive the list for group member public keys
            self.p2p_chat_group(address, group_port)
        elif command == 2 and access_level == 1:
            name_add = input("Enter a username: ")
            self.send_message(f"{name_add},{group_name}")
            # Sending the certificate to the client using the private chat
            self.private_chat(groups[group_name][1], name_add)
            print(f"Added {name_add} to {group_name}")
        elif command == 3 and access_level == 1:
            name_modify = input("Enter a username: ")
            level_modify = input("Enter an access level (0/1): ")
            self.send_message(f"{name_modify},{level_modify},{group_name}")
            print(f"User {name_modify} with access level {level_modify} for group {group_name}")
        else:
            print("Invalid command or insufficient access level")

    def create_group_chat(self):
        self.send_message("CreatingGroupChat")

        # Send public key to server to check signature
        self.send_message(f"PUBLIC_KEY:{self.public_key.decode()}")
        group_name = input("Enter group name: ")

        # Sign the username before sending
        message = self.username + ',' + group_name
        # Encrypt the message with AES
        aes_key = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
        # Compute HMAC
        hmac = HMAC.new(aes_key, digestmod=SHA256)
        hmac.update(ciphertext + tag)
        hmac_tag = hmac.digest()
        # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
        data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
        h = SHA256.new(data_to_sign)
        signature = pkcs1_15.new(self.key).sign(h)
        final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
        self.send_message(final_message)

        # Receive a new unique port number in which the client listens on
        received = self.receive_message()
        if received == "Not allowed":
            print("You are not allowed to create a group! (access level = 0)")
        elif received == "exists":
            print("Group name already taken. Please choose another.")
        else:
            group_port = int(received)
            print("Admin group port received to listen on:", group_port)
            # certificate = self.socket.recv(4096)
            # print("CERT:", str(certificate))
            admin_thread = threading.Thread(target=self.start_group_server, args=(group_port, group_name,), daemon=True) # ,certificate
            admin_thread.start()

    def private_chat(self, group_certificate=None, recipient_username=None):
        self.send_message("privateChat")
        if recipient_username is None:
            recipient_username = input("Enter recipient username: ")
        self.send_message(recipient_username)

        p2p_info_confirm = self.receive_message()
        if p2p_info_confirm == "P2P_INFO":
            p2p_info = self.receive_message()
            print('P2P info', p2p_info)  # Connect the port which the other client is listening
            address, port = p2p_info.split(":")
            self.p2p_chat(address, int(port), group_certificate, None)
        else:
            print("Failed to initiate private chat:", p2p_info_confirm)

    def p2p_chat(self, address, port, group_certificate=None, message=None):
        # Connect to this user's port and start chat
        recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        recipient_socket.connect((address, port))

        # Combine public key and certificate into a single message
        message_parts = ""
        if group_certificate is not None:
            message_parts += "CERT:" + group_certificate + ";"
        message_parts += "PUBLIC_KEY:" + self.public_key.decode()
        # Join the message parts with a delimiter and send the combined message
        recipient_socket.sendall(message_parts.encode('utf-8'))
        print("Group certificate and public key sent as", message_parts)

        # if group_certificate is not None:
        #     message = "CERT:" + group_certificate
        #     recipient_socket.sendall(message.encode('utf-8'))
        #     print("Group certificate sent as", message)
        # else:
        #     # Send the public key to the peer
        #     recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())

        if message is not None:  # message for group
            # message = f"*{self.username}*: " + message
            # Encrypt the message with AES
            aes_key = get_random_bytes(16)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

            # Compute HMAC
            hmac = HMAC.new(aes_key, digestmod=SHA256)
            hmac.update(ciphertext + tag)
            hmac_tag = hmac.digest()

            # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
            data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
            h = SHA256.new(data_to_sign)
            signature = pkcs1_15.new(self.key).sign(h)

            final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
            recipient_socket.sendall(final_message.encode())
        else:
            print("Start typing your messages (type 'exit' to end chat):")
            while True:
                message = input()
                if message == "exit":
                    break
                message = f"*{self.username}*: " + message
                # Encrypt the message with AES
                aes_key = get_random_bytes(16)
                cipher_aes = AES.new(aes_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

                # Compute HMAC
                hmac = HMAC.new(aes_key, digestmod=SHA256)
                hmac.update(ciphertext + tag)
                hmac_tag = hmac.digest()

                # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
                data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
                h = SHA256.new(data_to_sign)
                signature = pkcs1_15.new(self.key).sign(h)

                final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
                recipient_socket.sendall(final_message.encode())

                print("Message sent.")

        recipient_socket.close()

    def start_group_server(self, group_port, group_name):  # , certificate
        group_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        group_socket.bind((HOST, group_port))
        group_socket.listen(1)
        print(f"Group server listening on port {group_port}")
        # groups[group_name] = (1,certificate) # Access level of admin
        # The admin keeps the member's ports for each group
        self.groups_member_ports[group_name] = set()

        while True:
            conn, addr = group_socket.accept()
            print(f"Connected to {addr}")
            threading.Thread(target=self.handle_group, args=(conn, group_name,)).start()  # handle_p2p_client(conn)

    def p2p_chat_group(self, address, port):
        global P2P_PORT

        # Connect to this user's port and start chat
        recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        recipient_socket.connect((address, port))

        # Combine the public key and port number into a single message
        message = f"PUBLIC_KEY:{self.username}:{self.public_key.decode()}|PortNum:{P2P_PORT}"
        recipient_socket.sendall(message.encode())
        print("Sending PortNum:", P2P_PORT)
        # # Send the public key to the peer
        # recipient_socket.sendall(f"PUBLIC_KEY:{self.username}:{self.public_key.decode()}".encode())
        # print("Sending PortNum:", P2P_PORT)
        # recipient_socket.sendall(f"PortNum:{P2P_PORT}".encode())

        print("Start typing your messages (type 'exit' to end chat):")
        while True:
            message = input()
            if message == "exit":
                break
            message = f"*{self.username}*: " + message
            # Encrypt the message with AES
            aes_key = get_random_bytes(16)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

            # Compute HMAC
            hmac = HMAC.new(aes_key, digestmod=SHA256)
            hmac.update(ciphertext + tag)
            hmac_tag = hmac.digest()

            # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
            data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
            h = SHA256.new(data_to_sign)
            signature = pkcs1_15.new(self.key).sign(h)

            final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
            recipient_socket.sendall(final_message.encode())

            print("Message sent.")

        recipient_socket.close()


        # global firstPVChat_flag
        # recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # recipient_socket.connect((address, port))
        #
        # # Send the public key to the peer
        # if firstPVChat_flag:
        #     recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())
        #     firstPVChat_flag = False
        #
        # # Encrypt the message with AES
        # aes_key = get_random_bytes(16)
        # cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        # ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
        #
        # # Compute HMAC
        # hmac = HMAC.new(aes_key, digestmod=SHA256)
        # hmac.update(ciphertext + tag)
        # hmac_tag = hmac.digest()
        #
        # # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
        # data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
        # h = SHA256.new(data_to_sign)
        # signature = pkcs1_15.new(self.key).sign(h)
        #
        # final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
        # recipient_socket.sendall(final_message.encode())
        #
        # recipient_socket.close()
        # firstPVChat_flag = True

    # def handle_group(self, conn, group_name):
    #     global peer_public_key
    #     global group_member_pk
    #     print("Connection:", conn)
    #     with conn:
    #         port_num = None
    #         while True:
    #             data = conn.recv(1024)
    #             if not data:
    #                 break
    #             message = data.decode()
    #             if message.startswith("PUBLIC_KEY:"):
    #                 # Receive and set the peer's public key
    #                 # GET THE PUBLIC KEY OF THIS USER WITH THE MEMBER TABLE IN SERVER !!!!!!!!!!!!!!!11
    #                 # AFTER THAT USE THAT PUBLIC KEY TO DO THE REST
    #                 peer_public_key_pem = message.split(":")[2]
    #                 # print("PEM", peer_public_key_pem)
    #                 peer_public_key = peer_public_key_pem.encode()
    #                 print("Received peer's public key.")
    #             elif message.startswith("PortNum:"):
    #                 port_num = message.split(":")[1]
    #                 print("Port num that is connected to me:", port_num)
    def handle_group(self, conn, group_name):
        global peer_public_key
        global group_member_pk
        print("Connection:", conn)
        with conn:
            port_num = None
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                message = data.decode()

                # Check if the message contains both public key and port number
                if '|' in message:
                    parts = message.split('|')
                    for part in parts:
                        if part.startswith("PUBLIC_KEY:"):
                            # Receive and set the peer's public key
                            peer_public_key_pem = part.split(":")[2]
                            peer_public_key = peer_public_key_pem.encode()
                            print("Received peer's public key.")
                        elif part.startswith("PortNum:"):
                            port_num = part.split(":")[1]
                            print("Port num that is connected to me:", port_num)
                else:
                    # Split the received data into components
                    parts = message.split(":")
                    if len(parts) == 7:
                        sender_username, nonce, aes_key, ciphertext, tag, hmac_tag, signed_message = parts
                        nonce = base64.b64decode(nonce)
                        aes_key = base64.b64decode(aes_key)
                        ciphertext = base64.b64decode(ciphertext)
                        tag = base64.b64decode(tag)
                        hmac_tag = base64.b64decode(hmac_tag)
                        signature = base64.b64decode(signed_message)

                        try:
                            peer_public_key = group_member_pk[port_num]
                        except KeyError:
                            print(f"KeyError: Port number {port_num} not found in group_member_pk")
                            return

                        # Verify the message
                        if peer_public_key:
                            peer_rsa_key = RSA.import_key(peer_public_key)
                            data_to_verify = nonce + aes_key + ciphertext + hmac_tag
                            h = SHA256.new(data_to_verify)
                            try:
                                pkcs1_15.new(peer_rsa_key).verify(h, signature)
                                # Verify HMAC
                                hmac = HMAC.new(aes_key, digestmod=SHA256)
                                hmac.update(ciphertext + tag)
                                hmac.verify(hmac_tag)

                                # Decrypt the message
                                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                                decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
                                final_message = decrypted_message.decode('utf-8')
                                print(final_message)  # "Received message:",
                            except (ValueError, TypeError) as e:
                                print("Signature verification failed.", str(e))

                            # When it receives a message, it should send it to everyone but itself
                            # print("group_member_ports:", self.groups_member_ports[group_name])
                            member_ports = self.groups_member_ports[group_name]
                            # If the set was not empty, send the message to ports
                            for mp in member_ports:
                                print("SENDING MESSAGE", final_message,"TO PORT", mp)
                                if mp != P2P_PORT: # Connect and Send the received message to this port
                                    print("Connecting and sending the message to port", mp)
                                    self.p2p_chat('localhost', mp, None, final_message)

                        else:
                            print("Peer public key not received. Cannot verify message.")
                    else:
                        print("Received message format is incorrect.")



def start_p2p_server():
    p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    p2p_socket.bind((HOST, P2P_PORT))
    p2p_socket.listen(1)
    print(f"P2P server listening on port {P2P_PORT}")

    while True:
        conn, addr = p2p_socket.accept()
        print(f"Connected to {addr}")
        threading.Thread(target=handle_p2p_client, args=(conn,)).start()


def handle_p2p_client(conn):
    global peer_public_key
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = data.decode()
            # print("***The message:***",message)
            if message.startswith("PUBLIC_KEY:"):
                # Receive and set the peer's public key
                peer_public_key_pem = message.split("PUBLIC_KEY:")[1]
                peer_public_key = peer_public_key_pem.encode()
                print("Received peer's public key.")
            elif message.startswith("CERT:"):
                certi = message.split(";")[0][5:]
                peer_public_key_pem = message.split(";")[1].split("PUBLIC_KEY:")[1]
                peer_public_key = peer_public_key_pem.encode()
                print("Received peer's public key.")
                print("Received certificate:", certi)
            else:
                # print("Received", message)
                # Split the received data into components
                parts = message.split(":")
                if len(parts) == 7:
                    sender_username, nonce, aes_key, ciphertext, tag, hmac_tag, signed_message = parts
                    nonce = base64.b64decode(nonce)
                    aes_key = base64.b64decode(aes_key)
                    ciphertext = base64.b64decode(ciphertext)
                    tag = base64.b64decode(tag)
                    hmac_tag = base64.b64decode(hmac_tag)
                    signature = base64.b64decode(signed_message)

                    # Verify the message
                    if peer_public_key:
                        peer_rsa_key = RSA.import_key(peer_public_key)
                        data_to_verify = nonce + aes_key + ciphertext + hmac_tag
                        h = SHA256.new(data_to_verify)
                        try:
                            pkcs1_15.new(peer_rsa_key).verify(h, signature)
                            print("Signature is valid.")

                            # Verify HMAC
                            hmac = HMAC.new(aes_key, digestmod=SHA256)
                            hmac.update(ciphertext + tag)
                            hmac.verify(hmac_tag)

                            # Decrypt the message
                            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                            decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
                            print(decrypted_message.decode('utf-8'))  # "Received message:",
                        except (ValueError, TypeError) as e:
                            print("Signature verification failed.", str(e))
                    else:
                        print("Peer public key not received. Cannot verify message.")
                else:
                    print("Received message format is incorrect.")





def main():
    client = Client()
    client.run()


if __name__ == "__main__":
    main()




# import json
# import socket
# import threading
# import base64
#
# from Crypto.Hash import SHA256, HMAC
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP, AES
# from Crypto.Random import get_random_bytes
# from Crypto.Signature import pkcs1_15
#
# HOST = 'localhost'
# PORT = 12345
# P2P_PORT = 12346
# peer_public_key = None
# # firstPVChat_flag = True
# group_member_pk = dict()  # port:publicKey, port2:publicKey2, ...
#
# class Client:
#     def __init__(self):
#         global peer_public_key
#         self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.socket.connect((HOST, PORT))
#         self.username = None
#         # Generate RSA key pair
#         self.key = RSA.generate(2048)
#         self.public_key = self.key.publickey().export_key()
#
#         self.access_level = 1  # Access level to build a group
#         self.groups_member_ports = dict()
#
#     def run(self):
#         try:
#             while True:
#                 print("1. Register")
#                 print("2. Login")
#                 print("3. Exit")
#                 print("4. Private Chat")
#                 print("5. Group Chats")
#                 if self.access_level == 1:
#                     print("6. Create Group Chat")
#
#                 choice = input("Enter your choice: ")
#
#                 if choice == "1":
#                     self.register_user()
#                 elif choice == "2":
#                     self.login_user()
#                 elif choice == "3":
#                     print("Exiting...")
#                     break
#                 elif choice == "4":
#                     self.private_chat()
#                 elif choice == "5":
#                     self.enter_group_chat()
#                 elif choice == "6" and self.access_level == 1:
#                     self.create_group_chat()
#                 else:
#                     print("Invalid choice!")
#
#         except Exception as e:
#             print("Client exception:", str(e))
#
#     def send_message(self, message):
#         self.socket.sendall(message.encode())
#
#     def receive_message(self):
#         return self.socket.recv(1024).decode()
#
#     def register_user(self):
#         self.send_message("register")
#         email = input("Enter your email: ")
#         self.send_message(email)
#         username = input("Enter your username: ")
#         self.send_message(username)
#         password = input("Enter your password: ")
#         self.send_message(password)
#         confirm_password = input("Confirm your password: ")
#         self.send_message(confirm_password)
#         # Send public key
#         self.send_message(self.public_key.decode())
#
#         print(self.receive_message())
#
#     def login_user(self):
#         global P2P_PORT
#         global group_member_pk
#
#         self.send_message("login")
#         self.username = input("Enter your username: ")
#         self.send_message(self.username)
#         password = input("Enter your password: ")
#         self.send_message(password)
#         # Get the p2p port number which is unique
#         response = self.receive_message()
#         print(response)
#         if response == "Login failed!":
#             return
#         P2P_PORT = int(self.receive_message())
#         p2p_thread = threading.Thread(target=start_p2p_server, daemon=True)
#         p2p_thread.start()
#         # self.send_message(str(P2P_PORT))
#
#     def enter_group_chat(self):
#         self.send_message("EnterGroups")
#         print("--- Your Groups ---")
#         # self.send_message(self.username)
#         try:
#             # Receive the JSON-encoded groups dictionary
#             groups_json = self.socket.recv(4096).decode('utf-8')
#             # Deserialize the JSON string to a dictionary
#             groups = json.loads(groups_json)
#         except (json.JSONDecodeError, KeyError):
#             print("Failed to decode groups data")
#             return
#
#         if not groups:
#             print("No groups found")
#             return
#
#         for group, details in groups.items():
#             print(f'{group} (access level {details[0]})')
#
#         group_name = input("Enter the group name: ")
#
#         if group_name not in groups:
#             print("Group does not exist")
#             return
#
#         print("1. Enter group")
#         access_level = groups[group_name][0]
#
#         if access_level == 1:
#             print("2. Add to group")
#             print("3. Modify user access levels")
#
#         try:
#             command = int(input("Enter your choice: "))
#         except ValueError:
#             print("Invalid input")
#             return
#
#         self.send_message(str(command))
#
#         if command == 1:
#             global group_member_pk
#             group_member_pk = dict()
#             # Send the port number to the server to get the group port number and connect
#             print(f"Entered group {group_name}")
#             self.send_message(group_name)
#             group_port = int(self.receive_message())
#             print("Received group port", group_port)
#             address = 'localhost'
#             # admin: Getting this group's user ports from server so that every message is sent to others
#             if access_level == 1:
#                 member_ports_str = self.receive_message()
#                 pk_temp = self.receive_message()  # in format port1:pk1,port2:pk2,...
#                 pk_temp2 = dict()
#                 self.groups_member_ports[group_name] = set(map(int, member_ports_str.split(",")))
#                 print("Member Ports:", self.groups_member_ports[group_name])
#                 # switch to the correct format
#                 pk_temp2[group_name] = list(map(str, pk_temp.split(",")))
#                 for port_key_pair in pk_temp2:
#                     tempPortNum = port_key_pair.split(":")[0]
#                     tempKey_pem = port_key_pair.split(":")[1]
#                     group_member_pk[tempPortNum] = tempKey_pem.encode()
#
#             # Receive the list for group member public keys
#             self.p2p_chat_group(address, group_port)
#         elif command == 2 and access_level == 1:
#             name_add = input("Enter a username: ")
#             self.send_message(f"{name_add},{group_name}")
#             # Sending the certificate to the client using the private chat
#             self.private_chat(groups[group_name][1], name_add)
#             print(f"Added {name_add} to {group_name}")
#         elif command == 3 and access_level == 1:
#             name_modify = input("Enter a username: ")
#             level_modify = input("Enter an access level (0/1): ")
#             self.send_message(f"{name_modify},{level_modify},{group_name}")
#             print(f"User {name_modify} with access level {level_modify} for group {group_name}")
#         else:
#             print("Invalid command or insufficient access level")
#
#     def create_group_chat(self):
#         self.send_message("CreatingGroupChat")
#
#         # Send public key to server to check signature
#         self.send_message(f"PUBLIC_KEY:{self.public_key.decode()}")
#         group_name = input("Enter group name: ")
#
#         # Sign the username before sending
#         message = self.username + ',' + group_name
#         # Encrypt the message with AES
#         aes_key = get_random_bytes(16)
#         cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#         ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#         # Compute HMAC
#         hmac = HMAC.new(aes_key, digestmod=SHA256)
#         hmac.update(ciphertext + tag)
#         hmac_tag = hmac.digest()
#         # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
#         data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#         h = SHA256.new(data_to_sign)
#         signature = pkcs1_15.new(self.key).sign(h)
#         final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#         self.send_message(final_message)
#
#         # Receive a new unique port number in which the client listens on
#         received = self.receive_message()
#         if received == "Not allowed":
#             print("You are not allowed to create a group! (access level = 0)")
#         elif received == "exists":
#             print("Group name already taken. Please choose another.")
#         else:
#             group_port = int(received)
#             print("Admin group port received to listen on:", group_port)
#             # certificate = self.socket.recv(4096)
#             # print("CERT:", str(certificate))
#             admin_thread = threading.Thread(target=self.start_group_server, args=(group_port, group_name,), daemon=True) # ,certificate
#             admin_thread.start()
#
#     def private_chat(self, group_certificate=None, recipient_username=None):
#         if recipient_username is None:
#             self.send_message("privateChat")
#             recipient_username = input("Enter recipient username: ")
#         self.send_message(recipient_username)
#         p2p_info_confirm = self.receive_message()
#         if p2p_info_confirm.startswith("P2P_INFO"):
#             p2p_info = self.receive_message()
#             print('P2P info', p2p_info)  # Connect the port which the other client is listening
#             address, port = p2p_info.split(":")
#             self.p2p_chat(address, int(port), group_certificate)
#         else:
#             print("Failed to initiate private chat:", p2p_info_confirm)
#
#     def p2p_chat(self, address, port, group_certificate=None, message=None):
#         # Connect to this user's port and start chat
#         # global firstPVChat_flag
#         recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         recipient_socket.connect((address, port))
#
#         # Send the public key to the peer
#         # if firstPVChat_flag:
#
#             # firstPVChat_flag = False
#
#         if group_certificate is not None:
#             pk_pem = self.public_key.decode()
#             message = pk_pem + "CERT:" + group_certificate
#             recipient_socket.sendall(message.encode('utf-8'))
#             print("Group certificate sent as", message)
#         else:
#             recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())
#
#         if message is not None:  # message for group
#             message = f"*{self.username}*: " + message
#             # Encrypt the message with AES
#             aes_key = get_random_bytes(16)
#             cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#             ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#
#             # Compute HMAC
#             hmac = HMAC.new(aes_key, digestmod=SHA256)
#             hmac.update(ciphertext + tag)
#             hmac_tag = hmac.digest()
#
#             # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
#             data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#             h = SHA256.new(data_to_sign)
#             signature = pkcs1_15.new(self.key).sign(h)
#
#             final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#             recipient_socket.sendall(final_message.encode())
#         else:
#             print("Start typing your messages (type 'exit' to end chat):")
#             while True:
#                 message = input()
#                 if message == "exit":
#                     break
#                 message = f"*{self.username}*: " + message
#                 # Encrypt the message with AES
#                 aes_key = get_random_bytes(16)
#                 cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#                 ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#
#                 # Compute HMAC
#                 hmac = HMAC.new(aes_key, digestmod=SHA256)
#                 hmac.update(ciphertext + tag)
#                 hmac_tag = hmac.digest()
#
#                 # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
#                 data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#                 h = SHA256.new(data_to_sign)
#                 signature = pkcs1_15.new(self.key).sign(h)
#
#                 final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#                 recipient_socket.sendall(final_message.encode())
#
#                 print("Message sent.")
#
#         # firstPVChat_flag = True
#         recipient_socket.close()
#
#     def start_group_server(self, group_port, group_name):  # , certificate
#         group_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         group_socket.bind((HOST, group_port))
#         group_socket.listen(1)
#         print(f"Group server listening on port {group_port}")
#         # groups[group_name] = (1,certificate) # Access level of admin
#         # The admin keeps the member's ports for each group
#         self.groups_member_ports[group_name] = set()
#
#         while True:
#             conn, addr = group_socket.accept()
#             print(f"Connected to {addr}")
#             threading.Thread(target=self.handle_group, args=(conn, group_name,)).start()  # handle_p2p_client(conn)
#
#     def p2p_chat_group(self, address, port):
#
#         # Connect to this user's port and start chat
#         # global firstPVChat_flag
#         recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         recipient_socket.connect((address, port))
#
#         # # Send the public key to the peer
#         # if firstPVChat_flag:
#         #     recipient_socket.sendall(f"PUBLIC_KEY:{self.username}:{self.public_key.decode()}".encode())
#         #     firstPVChat_flag = False
#
#         print("Start typing your messages (type 'exit' to end chat):")
#         while True:
#             message = input()
#             if message == "exit":
#                 break
#             message = f"*{self.username}*: " + message
#             # Encrypt the message with AES
#             aes_key = get_random_bytes(16)
#             cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#             ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#
#             # Compute HMAC
#             hmac = HMAC.new(aes_key, digestmod=SHA256)
#             hmac.update(ciphertext + tag)
#             hmac_tag = hmac.digest()
#
#             # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
#             data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#             h = SHA256.new(data_to_sign)
#             signature = pkcs1_15.new(self.key).sign(h)
#
#             final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#             recipient_socket.sendall(final_message.encode())
#
#             print("Message sent.")
#
#         # firstPVChat_flag = True
#         recipient_socket.close()
#
#
#         # global firstPVChat_flag
#         # recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         # recipient_socket.connect((address, port))
#         #
#         # # Send the public key to the peer
#         # if firstPVChat_flag:
#         #     recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())
#         #     firstPVChat_flag = False
#         #
#         # # Encrypt the message with AES
#         # aes_key = get_random_bytes(16)
#         # cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#         # ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#         #
#         # # Compute HMAC
#         # hmac = HMAC.new(aes_key, digestmod=SHA256)
#         # hmac.update(ciphertext + tag)
#         # hmac_tag = hmac.digest()
#         #
#         # # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
#         # data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#         # h = SHA256.new(data_to_sign)
#         # signature = pkcs1_15.new(self.key).sign(h)
#         #
#         # final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#         # recipient_socket.sendall(final_message.encode())
#         #
#         # recipient_socket.close()
#         # firstPVChat_flag = True
#
#     def handle_group(self, conn, group_name):
#         global peer_public_key
#         global group_member_pk
#         print("Connection:", conn)
#         with conn:
#             while True:
#                 data = conn.recv(1024)
#                 if not data:
#                     break
#                 # message = data.decode()
#                 # if message.startswith("PUBLIC_KEY:"):
#                 #     # Receive and set the peer's public key
#                 #     # GET THE PUBLIC KEY OF THIS USER WITH THE MEMBER TABLE IN SERVER !!!!!!!!!!!!!!!11
#                 #     # AFTER THAT USE THAT PUBLIC KEY TO DO THE REST
#                 #     portNum = conn.laddr[1]
#
#                 #     peer_public_key_pem = message.split(":")[2]
#                 #     peer_public_key = peer_public_key_pem.encode()
#                 #     print("Received peer's public key.")
#                 else:
#                     portNum = conn.getsockname()[1]
#                     message = data.decode()
#                     # Split the received data into components
#                     parts = message.split(":")
#                     if len(parts) == 7:
#                         sender_username, nonce, aes_key, ciphertext, tag, hmac_tag, signed_message = parts
#                         nonce = base64.b64decode(nonce)
#                         aes_key = base64.b64decode(aes_key)
#                         ciphertext = base64.b64decode(ciphertext)
#                         tag = base64.b64decode(tag)
#                         hmac_tag = base64.b64decode(hmac_tag)
#                         signature = base64.b64decode(signed_message)
#
#                         peer_public_key = group_member_pk[portNum]
#                         # Verify the message
#                         if peer_public_key:
#                             peer_rsa_key = RSA.import_key(peer_public_key)
#                             data_to_verify = nonce + aes_key + ciphertext + hmac_tag
#                             h = SHA256.new(data_to_verify)
#                             try:
#                                 pkcs1_15.new(peer_rsa_key).verify(h, signature)
#                                 # Verify HMAC
#                                 hmac = HMAC.new(aes_key, digestmod=SHA256)
#                                 hmac.update(ciphertext + tag)
#                                 hmac.verify(hmac_tag)
#
#                                 # Decrypt the message
#                                 cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
#                                 decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
#                                 final_message = decrypted_message.decode('utf-8')
#                                 print(final_message)  # "Received message:",
#
#                                 # When it receives a message, it should send it to everyone but itself
#                                 print("group_member_ports:", self.groups_member_ports[group_name])
#                                 member_ports = self.groups_member_ports[group_name]
#                                 # If the set was not empty, send the message to ports
#                                 for mp in member_ports:
#                                     if mp != P2P_PORT: # Connect and Send the received message to this port
#                                         print("Connecting and sending the message to port", mp)
#                                         self.p2p_chat('localhost', mp, final_message)
#
#
#                             except (ValueError, TypeError) as e:
#                                 print("Signature verification failed.", str(e))
#                         else:
#                             print("Peer public key not received. Cannot verify message.")
#                     else:
#                         print("Received message format is incorrect.")
#
# def start_p2p_server():
#     p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     p2p_socket.bind((HOST, P2P_PORT))
#     p2p_socket.listen(1)
#     print(f"P2P server listening on port {P2P_PORT}")
#
#     while True:
#         conn, addr = p2p_socket.accept()
#         print(f"Connected to {addr}")
#         threading.Thread(target=handle_p2p_client, args=(conn,)).start()
#
#
# def handle_p2p_client(conn):
#     global peer_public_key
#     with conn:
#         cert_group = None
#         while True:
#             data = conn.recv(1024)
#             if not data:
#                 break
#
#             message = data.decode()
#             print("***Recived message***", message)
#             if message.startswith("PUBLIC_KEY:"):
#                 # Receive and set the peer's public key
#                 cert_indx = message.find("CERT:")
#                 cert_group = message[cert_indx:]
#                 message = message[:cert_indx]
#                 peer_public_key_pem = message.split("PUBLIC_KEY:")[1]
#                 peer_public_key = peer_public_key_pem.encode()
#                 print("Received peer's public key.")
#             elif cert_group is not None:
#                 print("Received certificate:", cert_group)
#             elif message.startswith("CERT:"):
#                 print("Received certificate:", message[5:])
#             else:
#                 # print("Received", message)
#                 # Split the received data into components
#                 parts = message.split(":")
#                 if len(parts) == 7:
#                     sender_username, nonce, aes_key, ciphertext, tag, hmac_tag, signed_message = parts
#                     nonce = base64.b64decode(nonce)
#                     aes_key = base64.b64decode(aes_key)
#                     ciphertext = base64.b64decode(ciphertext)
#                     tag = base64.b64decode(tag)
#                     hmac_tag = base64.b64decode(hmac_tag)
#                     signature = base64.b64decode(signed_message)
#
#                     # Verify the message
#                     if peer_public_key:
#                         peer_rsa_key = RSA.import_key(peer_public_key)
#                         data_to_verify = nonce + aes_key + ciphertext + hmac_tag
#                         h = SHA256.new(data_to_verify)
#                         try:
#                             pkcs1_15.new(peer_rsa_key).verify(h, signature)
#                             print("Signature is valid.")
#
#                             # Verify HMAC
#                             hmac = HMAC.new(aes_key, digestmod=SHA256)
#                             hmac.update(ciphertext + tag)
#                             hmac.verify(hmac_tag)
#
#                             # Decrypt the message
#                             cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
#                             decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
#                             print(decrypted_message.decode('utf-8'))  # "Received message:",
#                         except (ValueError, TypeError) as e:
#                             print("Signature verification failed.", str(e))
#                     else:
#                         print("Peer public key not received. Cannot verify message.")
#                 else:
#                     print("Received message format is incorrect.")
#
#
#
#
#
# def main():
#     client = Client()
#     client.run()
#
#
# if __name__ == "__main__":
#     main()
#

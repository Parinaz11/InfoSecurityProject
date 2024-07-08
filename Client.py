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

ack_received = False
optionA = 0
optionB = 0
optionC = 0
optionD = 0
vote_count = 0
port_number_to_send = None
process_vote_response = False


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
                if 0 <= int(self.access_level) <= 3:
                    print("4. Private Chat")
                if 0 <= int(self.access_level) <= 2:
                    print("5. Group Chats")
                if 0 <= int(self.access_level) <= 1:
                    print("6. Create Group Chat")
                if int(self.access_level) == 0:
                    print("7. Change Access Levels")

                choice = input("Enter your choice: ")

                if choice == "1":
                    self.register_user()
                elif choice == "2":
                    self.login_user()
                elif choice == "3":
                    print("Exiting...")
                    break
                elif choice == "4" and (0 <= int(self.access_level) <= 3):
                    self.private_chat()
                elif choice == "5" and (0 <= int(self.access_level) <= 2):
                    self.enter_group_chat()
                elif choice == "6" and (0 <= int(self.access_level) <= 1):
                    self.create_group_chat()
                elif choice == "7" and int(self.access_level) == 0:
                    self.change_access_levels()
                else:
                    print("Invalid choice!")

        except Exception as e:
            print("Client exception:", str(e))

    def send_message(self, message):
        self.socket.sendall(message.encode())

    def receive_message(self):
        return self.socket.recv(1024).decode()

    def change_access_levels(self):
        self.send_message("ChangeACL")
        name = input("Enter the username to change access:")
        self.send_message(name)
        role = input("Choose the role of the user (role1/role2/role3/role4)")
        # get the port
        response = self.receive_message()
        if response == "UserNotFound":
            print("The user was not found.")
        else:
            change_port = int(response)
            to_change_mes = "CHANGE_AL:" + role[4:]
            self.p2p_chat('localhost', change_port, None, to_change_mes)

    def register_user(self):
        role = input("Enter your role(role1/role2/role3/role4): ")
        if role != "role1" and role != "role2" and role != "role3" and role != "role4":
            print("Wrong format (role1/role2/role3/role4)")
            role = "role4"
        self.access_level = role[4:]
        print("ROLE[4] was", self.access_level)
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
        p2p_thread = threading.Thread(target=self.start_p2p_server, daemon=True)
        p2p_thread.start()
        # self.send_message(str(P2P_PORT))

    def enter_group_chat(self):
        self.send_message("EnterGroups")
        print("--- Your Groups ---")
        self.send_message(self.username)
        try:
            # Receive the JSON-encoded groups dictionary
            groups_json = self.socket.recv(4096).decode('utf-8')
            # Deserialize the JSON string to a dictionary
            groups = json.loads(groups_json)
        except (json.JSONDecodeError, KeyError):
            self.send_message("FAILED_TO_DECODE")
            print("Failed to decode groups data")
            return

        if not groups:
            self.send_message("NoGroups")
            print("No groups found")
            return

        for group, details in groups.items():
            print(f'{group} (access level {details[0]})')

        group_name = input("Enter the group name: ")

        if group_name not in groups:
            self.send_message("GroupNameNotInGroups")
            print("Group does not exist")
            return

        print("1. Enter group")
        access_level = groups[group_name][0]

        if access_level == 1:
            print("2. Add to group")
            # print("3. Modify user access levels")

        try:
            command = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid input")
            return

        self.send_message(str(command))

        if command == 1:
            # Send the port number to the server to get the group port number and connect
            print(f"Entered group {group_name}")
            self.send_message(group_name)
            group_port = int(self.receive_message())
            print("Received group port", group_port)
            address = 'localhost'
            # Getting this group's user ports from server so that every message is sent to others
            if access_level == 1:
                member_ports_str = self.receive_message()
                self.groups_member_ports[group_name] = set(map(int, member_ports_str.split(",")))
                print("Member Ports:", self.groups_member_ports[group_name])
            self.p2p_chat(address, group_port)
        elif command == 2 and access_level == 1:
            name_add = input("Enter a username: ")
            self.send_message(f"{name_add},{group_name}")
            # Sending the certificate to the client using the private chat
            self.private_chat(groups[group_name][1], name_add)
            print(f"Added {name_add} to {group_name}")
        # elif command == 3 and access_level == 1:
        #     name_modify = input("Enter a username: ")
        #     level_modify = input("Enter an access level (0/1): ")
        #     self.send_message(f"{name_modify},{level_modify},{group_name}")
        #     print(f"User {name_modify} with access level {level_modify} for group {group_name}")
        else:
            print("Invalid command or insufficient access level")

    def create_group_chat(self):
        self.send_message("CreatingGroupChat")

        # Send public key to server to check signature
        self.send_message(f"PUBLIC_KEY:{self.public_key.decode()}")
        group_name = input("Enter group name: ")

        # Sing the username before sending
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
            print("You are not allowed to create a group!")
        elif received == "exists":
            print("Group name already taken. Please choose another.")
        else:
            group_port = int(received)
            print("Group port received:", group_port)
            # certificate = self.socket.recv(4096)
            # print("CERT:", str(certificate))
            p2p_thread = threading.Thread(target=self.start_group_server, args=(group_port,group_name), daemon=True) # ,certificate
            p2p_thread.start()

    def private_chat(self, group_certificate=None, recipient_username=None):
        # if group_certificate is not None and recipient_username is not None:
        #     something
        # else:
        self.send_message("privateChat")
        ack_private_chat = self.receive_message()
        print(ack_private_chat)
        if recipient_username is None:
            recipient_username = input("Enter recipient username: ")
        self.send_message(recipient_username)

        p2p_info_confirm = self.receive_message()
        if p2p_info_confirm.startswith("P2P_INFO"):
            p2p_info = self.receive_message()
            print('P2P info', p2p_info)
            address, port = p2p_info.split(":")
            self.p2p_chat(address, int(port), group_certificate)
        else:
            print("Failed to initiate private chat:", p2p_info_confirm)

    def p2p_chat(self, address, port, group_certificate=None, message=None):
        global ack_received
        global optionA
        global optionB
        global optionC
        global optionD
        global vote_count
        global process_vote_response
        recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        recipient_socket.connect((address, port))

        # Send the public key to the peer
        recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())

        if group_certificate is not None:
            message = "CERT:" + group_certificate
            recipient_socket.sendall(message.encode('utf-8'))
            print("Group certificate sent as", message)

        elif message is None and group_certificate is None:
            print("Start typing your messages (type 'exit' to end chat):")
            while True:
                if process_vote_response:
                    answer = "p_ANSWER:"
                    response = "Z"
                    while response != "A" and response != "C" and response != "D" and response != "B":
                        response = input("Choose A/B/C/D: ")
                    answer += response
                    print("ANSWER =", answer)
                    if port_number_to_send is not None:
                        print("Sent answer", answer, "to voter")
                        self.p2p_chat_group('localhost', port_number_to_send, answer)
                    else:
                        print("Port number not set")
                    process_vote_response = False
                elif ack_received:
                    # Create the poll
                    poll_message = 'POLL:'
                    poll_q = input("Enter the poll question: ")
                    poll_message += poll_q + ";"
                    a = input("Enter option a) ")
                    poll_message += a + ";"
                    b = input("Enter option b) ")
                    poll_message += b + ";"
                    c = input("Enter option c) ")
                    poll_message += c + ";"
                    d = input("Enter option d) ")
                    poll_message += d
                    message = poll_message
                    ack_received = False
                else:
                    message = input()
                if message == "exit":
                    break
                elif message == "Voting":
                    message += f":{P2P_PORT}"
                    print('Enter "show result" to share the voting results')
                elif message == "show result":
                    # Choose the winner
                    winner_count = 0
                    winner = None
                    if optionA > winner_count:
                        winner_count = optionA
                        winner = "A"
                    if optionB > winner_count:
                        winner_count = optionB
                        winner = "B"
                    if optionC > winner_count:
                        winner_count = optionC
                        winner = "C"
                    if optionD > winner_count:
                        winner_count = optionD
                        winner = "D"
                    if winner is not None:
                        message = "Winner:*" + winner + "* chosen with score " + str(winner_count)
                    else:
                        message = "Voting not done"

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
        if message is not None:
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

        recipient_socket.close()

    def start_group_server(self, group_port, group_name):  # , certificate
        group_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        group_socket.bind((HOST, group_port))
        group_socket.listen(1)
        print(f"Group server listening on port {group_port}")
        # groups[group_name] = (1,certificate) # Access level of admin
        self.groups_member_ports[group_name] = set()

        while True:
            conn, addr = group_socket.accept()
            threading.Thread(target=self.handle_group, args=(conn, group_name,)).start()  # handle_p2p_client(conn)

    def p2p_chat_group(self, address, port, message):
        recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        recipient_socket.connect((address, port))

        # Send the public key to the peer
        recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())

        if message is not None:
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

        recipient_socket.close()

    def handle_group(self, conn, group_name):
        global peer_public_key
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                message = data.decode()
                if message.startswith("PUBLIC_KEY:"):
                    # Receive and set the peer's public key
                    peer_public_key_pem = message.split("PUBLIC_KEY:")[1]
                    peer_public_key = peer_public_key_pem.encode()
                    print("Received peer's public key.")
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

                                # When it receives a message, it should send it to everyone but itself
                                # print("group_member_ports:", self.groups_member_ports[group_name])
                                member_ports = self.groups_member_ports[group_name]
                                if member_ports:
                                    # If the set was not empty, send the message to ports
                                    for mp in member_ports:
                                        if mp != P2P_PORT:
                                            # Connect and Send the received message to this port
                                            # print("Connecting and sending the message to port", mp)
                                            self.p2p_chat_group('localhost', mp, final_message)

                            except (ValueError, TypeError) as e:
                                print("Signature verification failed.", str(e))
                        else:
                            print("Peer public key not received. Cannot verify message.")
                    else:
                        print("Received message format is incorrect.")

    def handle_p2p_client(self, conn):
        global peer_public_key
        global ack_received
        global optionA
        global optionB
        global optionC
        global optionD
        global vote_count
        global port_number_to_send
        global process_vote_response
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break

                message = data.decode()
                print("**MESSAGE IS", message)
                if message.startswith("PUBLIC_KEY:"):
                    # Receive and set the peer's public key
                    peer_public_key_pem = message.split("PUBLIC_KEY:")[1]
                    peer_public_key = peer_public_key_pem.encode()
                    print("Received peer's public key.")
                elif message.startswith("CERT:"):
                    print("Received certificate:", message[5:])
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
                                received_mes = decrypted_message.decode('utf-8')
                                print(received_mes)  # "Received message:",
                                # Voting
                                print("RECIVED MES", received_mes)
                                if received_mes.__contains__("Voting") and received_mes != "Voting ACK":
                                    print("REC message is", received_mes)
                                    if received_mes.split(":")[1] == " Voting":  # Received_mes format -> Voting:12348
                                        print("Sending voting ack to port", received_mes.split(":")[2])
                                        port_number_to_send = int(received_mes.split(":")[2])
                                        self.p2p_chat_group('localhost', port_number_to_send, "Voting ACK")
                                elif received_mes.__contains__("CHANGE_AL"):
                                    new_role = received_mes.split(":")[2]
                                    print("Changing access level to", new_role)
                                    self.access_level = new_role
                                elif received_mes == "Voting ACK":
                                    optionA = 0
                                    optionB = 0
                                    optionC = 0
                                    optionD = 0
                                    vote_count = 0
                                    ack_received = True
                                elif received_mes.__contains__("POLL"):  # with format *alice*:POLL:pollmessage
                                    poll_mes = received_mes.split(":")[2]
                                    poll_arr = poll_mes.split(";")
                                    print("--- Voting ---")
                                    print("Question: " + poll_arr[0])
                                    print("A) " + poll_arr[1])
                                    print("B) " + poll_arr[2])
                                    print("C) " + poll_arr[3])
                                    print("D) " + poll_arr[4])
                                    process_vote_response = True
                                elif received_mes.startswith("p_ANSWER:"):
                                    vote_count += 1
                                    vote_option = received_mes.split(":")[1]
                                    print("VOTE OPTION:")
                                    if vote_option == "A": optionA += 1
                                    if vote_option == "B": optionB += 1
                                    if vote_option == "C": optionC += 1
                                    if vote_option == "D": optionD += 1

                                elif received_mes.__contains__("Winner"):
                                    winner_mes = received_mes.split(":")[2]
                                    self.p2p_chat_group('localhost', port_number_to_send, winner_mes)

                            except (ValueError, TypeError) as e:
                                print("Signature verification failed.", str(e))
                        else:
                            print("Peer public key not received. Cannot verify message.")
                    else:
                        print("Received message format is incorrect.")

    def start_p2p_server(self):
        p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        p2p_socket.bind((HOST, P2P_PORT))
        p2p_socket.listen(1)
        print(f"P2P server listening on port {P2P_PORT}")

        while True:
            conn, addr = p2p_socket.accept()
            # print(f"Connected to {addr}")
            threading.Thread(target=self.handle_p2p_client, args=(conn,)).start()


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
#
#
# class Client:
#     def __init__(self):
#         global peer_public_key
#         self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.socket.connect((HOST, PORT))
#         self.username = None
#         self.key = RSA.generate(2048)
#         self.public_key = self.key.publickey().export_key()
#         self.access_level = 0  # Access level to build a group
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
#         role = input("Enter your role(admin/user): ")
#         if role == "admin":
#             self.access_level = 1
#         elif role == "user":
#             self.access_level = 0
#         else:
#             print("Wrong format. (admin/user)")
#         self.send_message("register")
#         email = input("Enter your email: ")
#         self.send_message(email)
#         username = input("Enter your username: ")
#         self.send_message(username)
#         password = input("Enter your password: ")
#         self.send_message(password)
#         confirm_password = input("Confirm your password: ")
#         self.send_message(confirm_password)
#         self.send_message(self.public_key.decode())
#         print(self.receive_message())
#
#     def login_user(self):
#         global P2P_PORT
#         self.send_message("login")
#         self.username = input("Enter your username: ")
#         self.send_message(self.username)
#         password = input("Enter your password: ")
#         self.send_message(password)
#         P2P_PORT = int(self.receive_message())
#         p2p_thread = threading.Thread(target=start_p2p_server, daemon=True)
#         p2p_thread.start()
#         print(self.receive_message())
#
#     def enter_group_chat(self):
#         self.send_message("EnterGroups")
#         print("--- Your Groups ---")
#         self.send_message(self.username)
#         try:
#             groups_json = self.socket.recv(4096).decode('utf-8')
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
#             print(f"Entered group {group_name}")
#             self.send_message(group_name)
#             group_port = int(self.receive_message())
#             print("Received group port", group_port)
#             address = 'localhost'
#             if access_level == 1:
#                 member_ports_str = self.receive_message()
#                 self.groups_member_ports[group_name] = set(map(int, member_ports_str.split(",")))
#                 print("Member Ports:", self.groups_member_ports[group_name])
#             self.p2p_chat(address, group_port)
#         elif command == 2 and access_level == 1:
#             name_add = input("Enter a username: ")
#             self.send_message(f"{name_add},{group_name}")
#             self.private_chat(groups[group_name][1], name_add)
#             print(f"Added {name_add} to {group_name}")
#         elif command == 3 and access_level == 1:
#             name_modify = input("Enter a username: ")
#             level_modify = input("Enter an access level (0/1): ")
#             self.send_message(f"{name_modify},{level_modify},{group_name}")
#             response = self.receive_message()
#             print(f"Server response: {response}")
#             if response == "Success":
#                 print(f"User {name_modify} access level changed to {level_modify} in group {group_name}")
#             else:
#                 print(f"Failed to change access level for {name_modify}")
#         else:
#             print("Invalid command or insufficient access level")
#
#     def create_group_chat(self):
#         self.send_message("CreatingGroupChat")
#         self.send_message(f"PUBLIC_KEY:{self.public_key.decode()}")
#         group_name = input("Enter group name: ")
#
#         message = self.username + ',' + group_name
#         aes_key = get_random_bytes(16)
#         cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#         ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#         hmac = HMAC.new(aes_key, digestmod=SHA256)
#         hmac.update(ciphertext + tag)
#         hmac_tag = hmac.digest()
#         data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#         h = SHA256.new(data_to_sign)
#         signature = pkcs1_15.new(self.key).sign(h)
#         final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#         self.send_message(final_message)
#
#         received = self.receive_message()
#         if received == "Not allowed":
#             print("You are not allowed to create a group!")
#         elif received == "exists":
#             print("Group name already taken. Please choose another.")
#         else:
#             group_port = int(received)
#             print("Group port received:", group_port)
#             p2p_thread = threading.Thread(target=self.start_group_server, args=(group_port, group_name), daemon=True)
#             p2p_thread.start()
#
#     def private_chat(self, group_certificate=None, recipient_username=None):
#         self.send_message("privateChat")
#         if recipient_username is None:
#             recipient_username = input("Enter recipient username: ")
#         self.send_message(recipient_username)
#
#         p2p_info_confirm = self.receive_message()
#         if p2p_info_confirm.startswith("P2P_INFO"):
#             p2p_info = self.receive_message()
#             print('P2P info', p2p_info)
#             address, port = p2p_info.split(":")
#             self.p2p_chat(address, int(port), group_certificate)
#         else:
#             print("Failed to initiate private chat:", p2p_info_confirm)
#
#     def p2p_chat(self, address, port, group_certificate=None, message=None):
#         recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         recipient_socket.connect((address, port))
#         recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())
#
#         if group_certificate is not None:
#             message = "CERT:" + group_certificate
#             recipient_socket.sendall(message.encode('utf-8'))
#             print("Group certificate sent as", message)
#         if message is not None:
#             message = f"*{self.username}*: " + message
#             aes_key = get_random_bytes(16)
#             cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#             ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#             hmac = HMAC.new(aes_key, digestmod=SHA256)
#             hmac.update(ciphertext + tag)
#             hmac_tag = hmac.digest()
#             data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#             h = SHA256.new(data_to_sign)
#             signature = pkcs1_15.new(self.key).sign(h)
#             final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#             recipient_socket.sendall(final_message.encode())
#         else:
#             print("Start typing your messages (type 'exit' to end chat):")
#             while True:
#                 message = input()
#                 if message == "exit":
#                     break
#                 message = f"*{self.username}*: " + message
#                 aes_key = get_random_bytes(16)
#                 cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#                 ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#                 hmac = HMAC.new(aes_key, digestmod=SHA256)
#                 hmac.update(ciphertext + tag)
#                 hmac_tag = hmac.digest()
#                 data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#                 h = SHA256.new(data_to_sign)
#                 signature = pkcs1_15.new(self.key).sign(h)
#                 final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#                 recipient_socket.sendall(final_message.encode())
#                 print("Message sent.")
#
#         recipient_socket.close()
#
#     def start_group_server(self, group_port, group_name):
#         group_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         group_socket.bind((HOST, group_port))
#         group_socket.listen(1)
#         print(f"Group server listening on port {group_port}")
#         self.groups_member_ports[group_name] = set()
#
#         while True:
#             conn, addr = group_socket.accept()
#             threading.Thread(target=self.handle_group, args=(conn, group_name,)).start()
#
#     def p2p_chat_group(self, address, port, message):
#         recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         recipient_socket.connect((address, port))
#         recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())
#
#         if message is not None:
#             aes_key = get_random_bytes(16)
#             cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#             ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#             hmac = HMAC.new(aes_key, digestmod=SHA256)
#             hmac.update(ciphertext + tag)
#             hmac_tag = hmac.digest()
#             data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#             h = SHA256.new(data_to_sign)
#             signature = pkcs1_15.new(self.key).sign(h)
#             final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#             recipient_socket.sendall(final_message.encode())
#
#         recipient_socket.close()
#
#     def handle_group(self, conn, group_name):
#         global peer_public_key
#         with conn:
#             while True:
#                 data = conn.recv(1024)
#                 if not data:
#                     break
#                 message = data.decode()
#                 if message.startswith("PUBLIC_KEY:"):
#                     peer_public_key_pem = message.split("PUBLIC_KEY:")[1]
#                     peer_public_key = peer_public_key_pem.encode()
#                     print("Received peer's public key.")
#                 else:
#                     parts = message.split(":")
#                     if len(parts) == 7:
#                         sender_username, nonce, aes_key, ciphertext, tag, hmac_tag, signed_message = parts
#                         nonce = base64.b64decode(nonce)
#                         aes_key = base64.b64decode(aes_key)
#                         ciphertext = base64.b64decode(ciphertext)
#                         tag = base64.b64decode(tag)
#                         hmac_tag = base64.b64decode(hmac_tag)
#                         signature = base64.b64decode(signed_message)
#                         if peer_public_key:
#                             peer_rsa_key = RSA.import_key(peer_public_key)
#                             data_to_verify = nonce + aes_key + ciphertext + hmac_tag
#                             h = SHA256.new(data_to_verify)
#                             try:
#                                 pkcs1_15.new(peer_rsa_key).verify(h, signature)
#                                 hmac = HMAC.new(aes_key, digestmod=SHA256)
#                                 hmac.update(ciphertext + tag)
#                                 hmac.verify(hmac_tag)
#                                 cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
#                                 decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
#                                 final_message = decrypted_message.decode('utf-8')
#                                 print(final_message)
#                                 member_ports = self.groups_member_ports[group_name]
#                                 if member_ports:
#                                     for mp in member_ports:
#                                         if mp != P2P_PORT:
#                                             self.p2p_chat_group('localhost', mp, final_message)
#                             except (ValueError, TypeError) as e:
#                                 print("Signature verification failed.", str(e))
#                         else:
#                             print("Peer public key not received. Cannot verify message.")
#                     else:
#                         print("Received message format is incorrect.")
#
#
# def start_p2p_server():
#     p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     p2p_socket.bind((HOST, P2P_PORT))
#     p2p_socket.listen(1)
#     print(f"P2P server listening on port {P2P_PORT}")
#
#     while True:
#         conn, addr = p2p_socket.accept()
#         threading.Thread(target=handle_p2p_client, args=(conn,)).start()
#
#
# def handle_p2p_client(conn):
#     global peer_public_key
#     with conn:
#         while True:
#             data = conn.recv(1024)
#             if not data:
#                 break
#
#             message = data.decode()
#             if message.startswith("PUBLIC_KEY:"):
#                 peer_public_key_pem = message.split("PUBLIC_KEY:")[1]
#                 peer_public_key = peer_public_key_pem.encode()
#                 print("Received peer's public key.")
#             elif message.startswith("CERT:"):
#                 print("Received certificate:", message[5:])
#             else:
#                 parts = message.split(":")
#                 if len(parts) == 7:
#                     sender_username, nonce, aes_key, ciphertext, tag, hmac_tag, signed_message = parts
#                     nonce = base64.b64decode(nonce)
#                     aes_key = base64.b64decode(aes_key)
#                     ciphertext = base64.b64decode(ciphertext)
#                     tag = base64.b64decode(tag)
#                     hmac_tag = base64.b64decode(hmac_tag)
#                     signature = base64.b64decode(signed_message)
#                     if peer_public_key:
#                         peer_rsa_key = RSA.import_key(peer_public_key)
#                         data_to_verify = nonce + aes_key + ciphertext + hmac_tag
#                         h = SHA256.new(data_to_verify)
#                         try:
#                             pkcs1_15.new(peer_rsa_key).verify(h, signature)
#                             print("Signature is valid.")
#                             hmac = HMAC.new(aes_key, digestmod=SHA256)
#                             hmac.update(ciphertext + tag)
#                             hmac.verify(hmac_tag)
#                             cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
#                             decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
#                             print(decrypted_message.decode('utf-8'))
#                         except (ValueError, TypeError) as e:
#                             print("Signature verification failed.", str(e))
#                     else:
#                         print("Peer public key not received. Cannot verify message.")
#                 else:
#                     print("Received message format is incorrect.")
#
#
# def main():
#     client = Client()
#     client.run()
#
#
# if __name__ == "__main__":
#     main()


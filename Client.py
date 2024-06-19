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
# groups = dict() # key:group name, value:(access level, certificate)

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
                    print("Working on enter group chat...")
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

        print(self.receive_message())

    def login_user(self):
        global P2P_PORT

        self.send_message("login")
        self.username = input("Enter your username: ")
        self.send_message(self.username)
        password = input("Enter your password: ")
        self.send_message(password)
        # Get the p2p port number which is unique
        P2P_PORT = int(self.receive_message())
        p2p_thread = threading.Thread(target=start_p2p_server, daemon=True)
        p2p_thread.start()
        # self.send_message(str(P2P_PORT))

        print(self.receive_message())

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
            print(f"Entered group {group_name}")
            self.send_message(group_name)
        elif command == 2 and access_level == 1:
            name_add = input("Enter a username: ")
            self.send_message(f"{name_add},{group_name}")
            print(f"Added {name_add} to {group_name}")
        elif command == 3 and access_level == 1:
            name_modify = input("Enter a username: ")
            level_modify = input("Enter an access level (0/1): ")
            self.send_message(f"{name_modify},{level_modify},{group_name}")
            print(f"User {name_modify} with access level {level_modify} for group {group_name}")
        else:
            print("Invalid command or insufficient access level")

    # def enter_group_chat(self):
    #     self.send_message("EnterGroups")
    #     print("--- Your Groups ---")
    #     self.send_message(self.username)
    #     # Receive the JSON-encoded groups dictionary
    #     groups_json = self.socket.recv(4096).decode('utf-8')
    #     # Deserialize the JSON string to a dictionary
    #     groups = json.loads(groups_json)
    #
    #     if groups:
    #         for group in groups:
    #             print(f'{group} (access level {groups.get(group)[0]})')
    #         group_name = input("Enter the group name: ")
    #         if group_name not in groups:
    #             print("Group does not exist")
    #         else:
    #             print("1. Enter group")
    #             al = groups.get(group_name)[0]
    #             if al == 1:
    #                 print("2. Add to group")
    #                 print("3. Modify user access levels")
    #
    #             command = int(input("Enter your choice: "))
    #             self.send_message(str(command))  # Send the command to server for processing
    #             if command == 1:
    #                 print(f"Entered group {group_name}")
    #                 self.send_message(group_name) # Sending the group name to server
    #             elif command == 2 and al == 1:
    #                 name_add = input("Enter a username:")
    #                 self.send_message(name_add + ',' + group_name) # Send the name to server
    #                 # !!! Getting the user's public key from the server and modifying the user's groups in server
    #                 # to have the access level and certificate for this group
    #                 # !!! it should send the certificate privately (works like p2p communication)
    #                 print(f"Added {name_add} to {group_name}")
    #             elif command == 3 and al == 1:
    #                 name_modify = input("Enter a username:")
    #                 level_modify = input("Enter an access level (0/1):")
    #                 print(f"User {name_modify} with access level {level_modify} for group {group_name}")
    #     else:
    #         print("No groups found")
    #
    #         Asking the server for port of the group


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
            p2p_thread = threading.Thread(target=start_group_server, args=(group_port,group_name), daemon=True) # ,certificate
            p2p_thread.start()


    def private_chat(self):
        self.send_message("privateChat")
        recipient_username = input("Enter recipient username: ")
        self.send_message(recipient_username)

        p2p_info_confirm = self.receive_message()
        if p2p_info_confirm.startswith("P2P_INFO"):
            p2p_info = self.receive_message()
            print('P2P info', p2p_info)
            address, port = p2p_info.split(":")
            self.p2p_chat(address, int(port))
        else:
            print("Failed to initiate private chat:", p2p_info_confirm)

    def p2p_chat(self, address, port):
        recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        recipient_socket.connect((address, port))

        # Send the public key to the peer
        recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())

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


def start_group_server(group_port, group_name): # , certificate
    group_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    group_socket.bind((HOST, group_port))
    group_socket.listen(1)
    print(f"Group server listening on port {group_port}")
    # groups[group_name] = (1,certificate) # Access level of admin

    while True:
        conn, addr = group_socket.accept()
        print(f"Connected to {addr}")
        threading.Thread(target=handle_group, args=(conn,)).start()

def handle_group(conn):
    print("Connection:", conn)

def main():
    client = Client()
    client.run()


if __name__ == "__main__":
    main()


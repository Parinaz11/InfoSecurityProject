import json
import random
import socket
import string
import threading
import hashlib
import base64
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pkcs1_15
from Cryptodome.PublicKey import RSA
from OpenSSL import crypto

PORT = 12345
HOST = 'localhost'
general_p2p_port = 12346
num_ports = 1
passphrase = b'123'


class User:
    def __init__(self, email, username, password_hash, salt, public_key_pem, address=None, p2p_port=None): # , public_key, private_key
        self.email = email
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.address = address
        self.p2p_port = p2p_port
        self.public_key = public_key_pem.encode()
        self.access_level = 1
        self.groups = dict()  # key:group name, value:(access level, certificate)


class UserManager:
    def __init__(self):
        self.users = []

    def register_user(self, email, username, password, confirm_password, public_key_pem):
        if password != confirm_password:
            return False

        if self.email_exists(email):
            return False

        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        # key_pair = RSA.generate(2048)
        user = User(email, username, hashed_password, salt, public_key_pem)  # , key_pair.publickey(), key_pair
        self.users.append(user)
        return True

    def login_user(self, username, password, address):
        user = self.find_user_by_username(username)
        if user:
            hashed_input_password = self.hash_password(password, user.salt)
            if hashed_input_password == user.password_hash:
                user.address = address
                return user
        return None

    def email_exists(self, email):
        for user in self.users:
            if user.email == email:
                return True
        return False

    def find_user_by_username(self, username):
        for user in self.users:
            if user.username == username:
                return user
        return None

    def generate_salt(self):
        return base64.b64encode(os.urandom(16)).decode()

    def hash_password(self, password, salt):
        return hashlib.sha256(salt.encode() + password.encode()).hexdigest()


class ClientHandler(threading.Thread):
    def __init__(self, socket, user_manager):
        super().__init__()
        self.socket = socket
        self.user_manager = user_manager
        self.username = None

    def run(self):
        with self.socket:
            try:
                while True:
                    command = self.receive_message()
                    print("###** command", command)
                    if command == "register":
                        self.handle_registration()
                    elif command == "login":
                        self.handle_login()
                    elif command == "privateChat":
                        self.send_message("received command")
                        self.handle_private_chat_request()
                    elif command == "CreatingGroupChat":
                        self.handle_create_group_chat()
                    elif command == "EnterGroups":
                        self.handle_enter_groups()
                    elif command == "ChangeACL":
                        self.change_access_levels()
                    else:
                        self.send_message("Unknown command!")

            except Exception as e:
                print("ClientHandler exception:", str(e))

            finally:
                if self.username:
                    with user_handlers_lock:
                        if self.username in user_handlers:
                            del user_handlers[self.username]

    def receive_message(self):
        return self.socket.recv(1024).decode()

    def send_message(self, message):
        self.socket.sendall(message.encode())

    def change_access_levels(self):
        name = self.receive_message()
        user_change = self.user_manager.find_user_by_username(name)
        if user_change is not None:
            self.send_message(str(user_change.p2p_port))
        else:
            self.send_message("UserNotFound")

    def handle_registration(self):
        email = self.receive_message()
        username = self.receive_message()
        password = self.receive_message()
        confirm_password = self.receive_message()
        public_key_pem = self.receive_message()
        success = self.user_manager.register_user(email, username, password, confirm_password, public_key_pem)
        self.send_message("Registration successful!" if success else "Registration failed!")

    def handle_login(self):
        global num_ports
        global general_p2p_port

        self.username = self.receive_message()
        password = self.receive_message()
        address = self.socket.getpeername()[0]
        user_created = self.user_manager.login_user(self.username, password, address)

        if user_created is not None:
            self.send_message("Login successful!")
            # send a unique port number
            num_ports += 1
            unique_port = general_p2p_port + num_ports
            user_created.p2p_port = unique_port

            self.send_message(str(unique_port))
            with user_handlers_lock:
                user_handlers[self.username] = self
            # p2p_port = int(self.receive_message())
        else:
            self.send_message("Login failed!")

    def handle_private_chat_request(self):
        recipient_username = self.receive_message()
        recipient_user = self.user_manager.find_user_by_username(recipient_username)
        if recipient_user:
            self.send_message("P2P_INFO")
            self.send_message(f"{recipient_user.address}:{recipient_user.p2p_port}")
        else:
            self.send_message("User does not exist.")

    def find_group_from_groupname(self, admin, group_name):
        for g in admin.groups:
            if g.name == group_name:
                return g

    def handle_enter_groups(self):
        user_username = self.receive_message()
        user = self.user_manager.find_user_by_username(user_username)
        self.send_message(json.dumps(user.groups))
        user_command = self.receive_message()

        if user_command == "FAILED_TO_DECODE" or user_command == "GroupNameNotInGroups" or user_command == "NoGroups":
            return

        if user_command == "1":
            group_name = self.receive_message()
            print(f"User {user.username} wants to connect to group {group_name}")
            # Send the port number of that group to the user
            print("Send port number ", str(groups_info[group_name][2]))
            self.send_message(str(groups_info[group_name][2]))
            # Send member ports of this group
            if user.access_level == 1:
                ports = ''
                for member in group_members[group_name]:
                    u = self.user_manager.find_user_by_username(member[0])
                    ports = ports + str(u.p2p_port) + ','  # Adding ports
                self.send_message(ports[:-1])  # Not sending the last character which is a comma

        elif user_command == "2":
            add_info = self.receive_message().split(',')
            name_add, group_name = add_info[0], add_info[1]
            with group_lock:
                user_to_add = self.user_manager.find_user_by_username(name_add)
                if user is not None:
                    group_certificate = user.groups[group_name][1]
                    user_to_add.groups[group_name] = (0, group_certificate)
                    group_members[group_name].add((user_to_add.username, user_to_add.public_key)) # Add a set
                    print("Group members now is:", group_members[group_name])
                    print(f"Added user {user_to_add.username} to group {group_name}")
                else:
                    print(f"User named {name_add} not found to add.")
            return
        # elif user_command == "3":
        #     modify_info = self.receive_message().split(',')
        #     name_modify, level_modify, group_name = modify_info[0], int(modify_info[1]), modify_info[2]
        #
        #     with group_lock:
        #         user_to_modify = self.user_manager.find_user_by_username(name_modify)
        #         if group_name in user.groups:
        #             user_to_modify.groups[group_name] = (level_modify, user.groups[group_name][1])
        #             group_members[group_name].add((user_to_modify, user_to_modify.public_key))
        #             print(f"Modified user {user_to_modify.username} access level to {level_modify} for group {group_name}")
        else:
            print(f"Unknown command {user_command}")

    def handle_create_group_chat(self):
        global num_ports
        global general_p2p_port

        # Receive public key of the user
        receive_key = self.receive_message()
        pk = None
        if receive_key.startswith("PUBLIC_KEY:"):
            # Receive and set the user's public key
            user_public_key_pem = receive_key.split("PUBLIC_KEY:")[1]
            user_public_key = user_public_key_pem.encode()
            pk = user_public_key

        id = None
        group_name = None
        # Checking the sign from user. Split the received data into components
        message = self.receive_message()
        parts = message.split(":")
        if len(parts) == 7:
            sender_username, nonce, aes_key, ciphertext, tag, hmac_tag, signed_message = parts
            user = self.user_manager.find_user_by_username(sender_username)
            user.public_key = pk
            nonce = base64.b64decode(nonce)
            aes_key = base64.b64decode(aes_key)
            ciphertext = base64.b64decode(ciphertext)
            tag = base64.b64decode(tag)
            hmac_tag = base64.b64decode(hmac_tag)
            signature = base64.b64decode(signed_message)
            # Verify the message
            if user.public_key:
                user_rsa_key = RSA.import_key(user.public_key)
                data_to_verify = nonce + aes_key + ciphertext + hmac_tag
                h = SHA256.new(data_to_verify)
                try:
                    pkcs1_15.new(user_rsa_key).verify(h, signature)
                    print("Signature is valid.")
                    # Verify HMAC
                    hmac = HMAC.new(aes_key, digestmod=SHA256)
                    hmac.update(ciphertext + tag)
                    hmac.verify(hmac_tag)
                    # Decrypt the message
                    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
                    print('ID, name: ' + decrypted_message.decode('utf-8'))  # "Received message:",
                    id = decrypted_message.decode('utf-8').split(',')[0]
                    group_name = decrypted_message.decode('utf-8').split(',')[1]
                    print("ID IS", id, "AND GROUP NAME IS", group_name)
                except (ValueError, TypeError) as e:
                    print("Signature verification failed.", str(e))
            else:
                print("Public key not received. Cannot verify message.")
        else:
            print("Received message format is incorrect.")

        # group_name = self.receive_message()
        user = self.user_manager.find_user_by_username(id)
        if user.access_level != 1:
            self.send_message("Not allowed")
        elif group_name in groups_info:
            # Shouldn't be accepted
            self.send_message("exists")
        else:
            with group_lock:
                # Sending a unique group port to this client
                num_ports += 1
                unique_group_port = general_p2p_port + num_ports
                groups_info[group_name] = (group_name, id, unique_group_port)
                self.send_message(str(unique_group_port))
                # Create and send a certificate for this user
                cert_pem = generate_certificate(pk, user.username)
                print(f"Generated Certificate: {cert_pem}")
                # Create the group with this certificate
                certificate = cert_pem.decode() # convert to string
                certificate = certificate[:70] # To shorten the certificate
                user.groups[group_name] = (1, certificate)  # Access level of admin
                if group_name in group_members:
                    group_members[group_name].add((user.username, user.public_key))   # Adding username and their public key
                else:
                    group_members[group_name] = set()
                    group_members[group_name].add((user.username, user.public_key))
                    if not group_members[group_name]:
                        print("The set is empty")


# Function to create a certificate using the user's public key
def generate_certificate(user_public_key, username):
    # Load CA certificate and key
    crt_path = r"C:\Users\parin\PycharmProjects\InfoSecurity\.venv\ca.crt"
    with open(crt_path, "rb") as ca_cert_file:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
    key_path = r"C:\Users\parin\PycharmProjects\InfoSecurity\.venv\ca.key"
    with open(key_path, "rb") as ca_key_file:
        content = ca_key_file.read()
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, content, passphrase)

    # More random and unique certificate
    cert = crypto.X509()
    cert.get_subject().CN = username
    cert.get_subject().O = ''.join(
        random.choices(string.ascii_letters + string.digits, k=8))  # Random organization name
    cert.get_subject().OU = ''.join(
        random.choices(string.ascii_letters + string.digits, k=8))  # Random organizational unit
    cert.get_subject().C = ''.join(random.choices(string.ascii_letters, k=2))  # Random country code
    cert.get_subject().ST = ''.join(random.choices(string.ascii_letters, k=8))  # Random state
    cert.get_subject().L = ''.join(random.choices(string.ascii_letters, k=8))  # Random locality
    cert.set_serial_number(int.from_bytes(os.urandom(16), byteorder='big'))  # Random serial number
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # Valid for 10 years
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(crypto.load_publickey(crypto.FILETYPE_PEM, user_public_key))
    cert.sign(ca_key, 'sha256')

    # Convert certificate to PEM format
    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    return cert_pem


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        print(f"Server is listening on port {PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"New connection from {addr}")

            client_handler = ClientHandler(client_socket, user_manager)
            client_handler.start()


if __name__ == "__main__":
    user_manager = UserManager()
    user_handlers = {}
    user_handlers_lock = threading.Lock()
    groups_info = {}  # Stores (group name, admin user id, group port)
    group_lock = threading.Lock()
    group_members = dict()  # Stores tuple (username, user public key)
    main()



#
# import json
# import random
# import socket
# import string
# import threading
# import hashlib
# import base64
# import os
#
# from Crypto.Cipher import AES
# from Crypto.Hash import SHA256, HMAC
# from Crypto.Signature import pkcs1_15
# from Crypto.PublicKey import RSA
# from Crypto.Random import get_random_bytes
# from OpenSSL import crypto
#
# PORT = 12345
# HOST = 'localhost'
# p2p_port = 12346
# num_ports = 1
# passphrase = b'123'
# # Generate RSA key pair
# key = RSA.generate(2048)
# public_key = key.publickey().export_key()
#
#
# class User:
#     def __init__(self, email, username, password_hash, salt, public_key_pem, address=None, p2p_port=None): # , public_key, private_key
#         self.email = email
#         self.username = username
#         self.password_hash = password_hash
#         self.salt = salt
#         self.address = address
#         self.p2p_port = p2p_port
#         self.public_key = public_key_pem.encode()
#         self.access_level = 1
#         self.groups = dict()  # key:group name, value:(access level, certificate)
#
#
# class UserManager:
#     def __init__(self):
#         self.users = []
#
#     def register_user(self, email, username, password, confirm_password, public_key_pem):
#         if password != confirm_password:
#             return False
#
#         if self.email_exists(email):
#             return False
#
#         salt = self.generate_salt()
#         hashed_password = self.hash_password(password, salt)
#         # key_pair = RSA.generate(2048)
#         user = User(email, username, hashed_password, salt, public_key_pem)  # , key_pair.publickey(), key_pair
#         self.users.append(user)
#         return True
#
#     def login_user(self, username, password, address, p2p_port):
#         user = self.find_user_by_username(username)
#         if user:
#             hashed_input_password = self.hash_password(password, user.salt)
#             if hashed_input_password == user.password_hash:
#                 user.address = address
#                 user.p2p_port = p2p_port
#                 return True
#         return False
#
#     def email_exists(self, email):
#         for user in self.users:
#             if user.email == email:
#                 return True
#         return False
#
#     def find_user_by_username(self, username):
#         for user in self.users:
#             if user.username == username:
#                 return user
#         return None
#
#     def generate_salt(self):
#         return base64.b64encode(os.urandom(16)).decode()
#
#     def hash_password(self, password, salt):
#         return hashlib.sha256(salt.encode() + password.encode()).hexdigest()
#
#
# class ClientHandler(threading.Thread):
#     def __init__(self, socket, user_manager):
#         super().__init__()
#         self.socket = socket
#         self.user_manager = user_manager
#         self.username = None
#
#     def run(self):
#         with self.socket:
#             try:
#                 while True:
#                     command = self.receive_message()
#                     if command == "register":
#                         self.handle_registration()
#                     elif command == "login":
#                         self.handle_login()
#                     elif command == "privateChat":
#                         self.handle_private_chat_request()
#                     elif command == "CreatingGroupChat":
#                         self.handle_create_group_chat()
#                     elif command == "EnterGroups":
#                         self.handle_enter_groups()
#                     elif command == "ChangeACL":
#                         self.handle_access()
#                     else:
#                         self.send_message("Unknown command!")
#
#             except Exception as e:
#                 print("ClientHandler exception:", str(e))
#
#             finally:
#                 if self.username:
#                     with user_handlers_lock:
#                         if self.username in user_handlers:
#                             del user_handlers[self.username]
#
#     def receive_message(self):
#         return self.socket.recv(1024).decode()
#
#     def send_message(self, message):
#         self.socket.sendall(message.encode())
#
#     def handle_registration(self):
#         email = self.receive_message()
#         username = self.receive_message()
#         password = self.receive_message()
#         confirm_password = self.receive_message()
#         public_key_pem = self.receive_message()
#         success = self.user_manager.register_user(email, username, password, confirm_password, public_key_pem)
#         self.send_message("Registration successful!" if success else "Registration failed!")
#
#     def handle_access(self):
#         name = self.receive_message()
#         user_change = self.user_manager.find_user_by_username(name)
#         if user_change is not None:
#             self.send_message(str(user_change.p2p_port))
#         else:
#             self.send_message("UserNotFound")
#
#     def handle_login(self):
#         global num_ports
#         global p2p_port
#         global public_key
#
#         self.username = self.receive_message()
#         password = self.receive_message()
#         address = self.socket.getpeername()[0]
#         # send a unique port number
#         num_ports += 1
#         unique_port = p2p_port + num_ports
#         self.send_message(str(unique_port))
#
#         success = self.user_manager.login_user(self.username, password, address, unique_port)
#         self.send_message("Login successful!" if success else "Login failed!")
#
#         if success:
#             with user_handlers_lock:
#                 user_handlers[self.username] = self
#
#     def handle_private_chat_request(self):
#         recipient_username = self.receive_message()
#         recipient_user = self.user_manager.find_user_by_username(recipient_username)
#         if recipient_user:
#             self.send_message("P2P_INFO")
#             self.send_message(f"{recipient_user.address}:{recipient_user.p2p_port}")
#         else:
#             self.send_message("User does not exist.")
#
#     def find_group_from_groupname(self, admin, group_name):
#         for g in admin.groups:
#             if g.name == group_name:
#                 return g
#
#     def handle_enter_groups(self):
#         user_username = self.receive_message()
#         user = self.user_manager.find_user_by_username(user_username)
#         self.send_message(json.dumps(user.groups))
#         user_command = self.receive_message()
#
#         if user_command == "1":
#             group_name = self.receive_message()
#             print(f"User {user.username} wants to connect to group {group_name}")
#             # Send the port number of that group to the user
#             # Encrypt with private key before sending
#             self.send_message(public_key.decode())
#             ack = self.receive_message()
#             if ack == "KEY ACK":
#                 print("Received key")
#
#             print("Send port number ", str(groups_info[group_name][2]))
#             message = str(groups_info[group_name][2])
#
#             if message is not None:
#                 original_message = message
#                 # Encrypt the message with AES
#                 aes_key = get_random_bytes(16)
#                 cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#                 ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
#                 # Compute HMAC
#                 hmac = HMAC.new(aes_key, digestmod=SHA256)
#                 hmac.update(ciphertext + tag)
#                 hmac_tag = hmac.digest()
#                 # Sign the concatenated nonce, AES key, ciphertext, and HMAC tag
#                 data_to_sign = cipher_aes.nonce + aes_key + ciphertext + hmac_tag
#                 h = SHA256.new(data_to_sign)
#                 signature = pkcs1_15.new(key).sign(h)
#                 # {original_message}:
#                 final_message = f"{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
#                 self.send_message(final_message)
#
#                 response_ack = self.receive_message()
#                 if response_ack == "ACK CORRECT":
#                     print("Correctly processed")
#                 else:
#                     print("Dropped")
#                     return
#
#         elif user_command == "2":
#             add_info = self.receive_message().split(',')
#             name_add, group_name = add_info[0], add_info[1]
#             with group_lock:
#                 user_to_add = self.user_manager.find_user_by_username(name_add)
#                 if user is not None:
#                     group_certificate = user.groups[group_name][1]
#                     user_to_add.groups[group_name] = (0, group_certificate)
#                     group_members[group_name].add((user_to_add.username, user_to_add.public_key)) # Add a set
#                     print("Group members now is:", group_members[group_name])
#                     print(f"Added user {user_to_add.username} to group {group_name}")
#                 else:
#                     print(f"User named {name_add} not found to add.")
#
#         elif user_command == "3":
#
#             add_info = self.receive_message().split(',')
#             name_add, group_name = add_info[0], add_info[1]
#             with group_lock:
#                 user_to_delete = self.user_manager.find_user_by_username(name_add)
#                 if user is not None:
#                     # del user_to_delete.groups[group_name]
#                     user_to_delete.groups.pop(group_name)
#                     print("***********", user_to_delete.groups)
#                     group_members[group_name].discard((user_to_delete.username, user_to_delete.public_key))   # Remove a set
#                     print("Group members now is:", group_members[group_name])
#                     print(f"deleted user {user_to_delete.username} from group {group_name}")
#
#                 else:
#                     print(f"User named {name_add} not found to add.")
#
#             # modify_info = self.receive_message().split(',')
#             # name_modify, level_modify, group_name = modify_info[0], int(modify_info[1]), modify_info[2]
#             #
#             # with group_lock:
#             #     user_to_modify = self.user_manager.find_user_by_username(name_modify)
#             #     if group_name in user.groups:
#             #         user_to_modify.groups[group_name] = (level_modify, user.groups[group_name][1])
#             #         group_members[group_name].add((user_to_modify, user_to_modify.public_key))
#             #         print(f"Modified user {user_to_modify.username} access level to {level_modify} for group {group_name}")
#         else:
#             print(f"Unknown command {user_command}")
#
#     def handle_create_group_chat(self):
#         global num_ports
#         global p2p_port
#
#         # Receive public key of the user
#         receive_key = self.receive_message()
#         pk = None
#         if receive_key.startswith("PUBLIC_KEY:"):
#             # Receive and set the user's public key
#             user_public_key_pem = receive_key.split("PUBLIC_KEY:")[1]
#             user_public_key = user_public_key_pem.encode()
#             pk = user_public_key
#
#         id = None
#         group_name = None
#         # Checking the sign from user. Split the received data into components
#         message = self.receive_message()
#         parts = message.split(":")
#         if len(parts) == 7:
#             sender_username, nonce, aes_key, ciphertext, tag, hmac_tag, signed_message = parts
#             user = self.user_manager.find_user_by_username(sender_username)
#             user.public_key = pk
#             nonce = base64.b64decode(nonce)
#             aes_key = base64.b64decode(aes_key)
#             ciphertext = base64.b64decode(ciphertext)
#             tag = base64.b64decode(tag)
#             hmac_tag = base64.b64decode(hmac_tag)
#             signature = base64.b64decode(signed_message)
#             # Verify the message
#             if user.public_key:
#                 user_rsa_key = RSA.import_key(user.public_key)
#                 data_to_verify = nonce + aes_key + ciphertext + hmac_tag
#                 h = SHA256.new(data_to_verify)
#                 try:
#                     pkcs1_15.new(user_rsa_key).verify(h, signature)
#                     print("Signature is valid.")
#                     # Verify HMAC
#                     hmac = HMAC.new(aes_key, digestmod=SHA256)
#                     hmac.update(ciphertext + tag)
#                     hmac.verify(hmac_tag)
#                     # Decrypt the message
#                     cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
#                     decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
#                     print('ID, name: ' + decrypted_message.decode('utf-8'))  # "Received message:",
#                     id = decrypted_message.decode('utf-8').split(',')[0]
#                     group_name = decrypted_message.decode('utf-8').split(',')[1]
#                     print("ID IS", id, "AND GROUP NAME IS", group_name)
#                 except (ValueError, TypeError) as e:
#                     print("Signature verification failed.", str(e))
#             else:
#                 print("Public key not received. Cannot verify message.")
#         else:
#             print("Received message format is incorrect.")
#
#         # group_name = self.receive_message()
#         user = self.user_manager.find_user_by_username(id)
#         if user.access_level != 1:
#             self.send_message("Not allowed")
#         elif group_name in groups_info:
#             # Shouldn't be accepted
#             self.send_message("exists")
#         else:
#             with group_lock:
#                 # Sending a unique group port to this client
#                 num_ports += 1
#                 unique_group_port = p2p_port + num_ports
#                 groups_info[group_name] = (group_name, id, unique_group_port)
#                 self.send_message(str(unique_group_port))
#                 # Create and send a certificate for this user
#                 cert_pem = generate_certificate(pk, user.username)
#                 print(f"Generated Certificate: {cert_pem}")
#                 # Create the group with this certificate
#                 certificate = cert_pem.decode() # convert to string
#                 user.groups[group_name] = (1, certificate)  # Access level of admin
#                 if group_name in group_members:
#                     group_members[group_name].add((user.username, user.public_key))   # Adding username and their public key
#                 else:
#                     group_members[group_name] = set()
#                     group_members[group_name].add((user.username, user.public_key))
#                     if not group_members[group_name]:
#                         print("The set is empty")
#
#
# # Function to create a certificate using the user's public key
# def generate_certificate(user_public_key, username):
#     # Load CA certificate and key
#     crt_path = r"C:\Users\parin\PycharmProjects\InfoSecurity\.venv\ca.crt"
#     with open(crt_path, "rb") as ca_cert_file:
#         ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
#     key_path = r"C:\Users\parin\PycharmProjects\InfoSecurity\.venv\ca.key"
#     with open(key_path, "rb") as ca_key_file:
#         content = ca_key_file.read()
#         ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, content, passphrase)
#
#     # More random and unique certificate
#     cert = crypto.X509()
#     cert.get_subject().CN = username
#     cert.get_subject().O = ''.join(
#         random.choices(string.ascii_letters + string.digits, k=8))  # Random organization name
#     cert.get_subject().OU = ''.join(
#         random.choices(string.ascii_letters + string.digits, k=8))  # Random organizational unit
#     cert.get_subject().C = ''.join(random.choices(string.ascii_letters, k=2))  # Random country code
#     cert.get_subject().ST = ''.join(random.choices(string.ascii_letters, k=8))  # Random state
#     cert.get_subject().L = ''.join(random.choices(string.ascii_letters, k=8))  # Random locality
#     cert.set_serial_number(int.from_bytes(os.urandom(16), byteorder='big'))  # Random serial number
#     cert.gmtime_adj_notBefore(0)
#     cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # Valid for 10 years
#     cert.set_issuer(ca_cert.get_subject())
#     cert.set_pubkey(crypto.load_publickey(crypto.FILETYPE_PEM, user_public_key))
#     cert.sign(ca_key, 'sha256')
#
#     # Convert certificate to PEM format
#     cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
#     return cert_pem
#
#
# def main():
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
#         server_socket.bind((HOST, PORT))
#         server_socket.listen()
#
#         print(f"Server is listening on port {PORT}")
#
#         while True:
#             client_socket, addr = server_socket.accept()
#             print(f"New connection from {addr}")
#
#             client_handler = ClientHandler(client_socket, user_manager)
#             client_handler.start()
#
#
# if __name__ == "__main__":
#     user_manager = UserManager()
#     user_handlers = {}
#     user_handlers_lock = threading.Lock()
#     groups_info = {}  # Stores (group name, admin user id, group port)
#     group_lock = threading.Lock()
#     group_members = dict()  # Stores tuple (username, user public key)
#     main()

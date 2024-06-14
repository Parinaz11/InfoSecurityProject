import socket
import threading
import hashlib
import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

PORT = 12345
HOST = 'localhost'
p2p_port = 12346
num_ports = 0

class User:
    def __init__(self, email, username, password_hash, salt, public_key, private_key, address=None, p2p_port=None):
        self.email = email
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.public_key = public_key  # Store public key
        self.private_key = private_key
        self.address = address
        self.p2p_port = p2p_port

class UserManager:
    def __init__(self):
        self.users = []

    def register_user(self, email, username, password, confirm_password):
        if password != confirm_password:
            return False

        if self.email_exists(email):
            return False

        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        key_pair = RSA.generate(2048)
        public_key_pem = key_pair.publickey().export_key()
        user = User(email, username, hashed_password, salt, public_key_pem, key_pair)
        self.users.append(user)
        return True

    def login_user(self, username, password, address, p2p_port):
        user = self.find_user_by_username(username)
        if user:
            hashed_input_password = self.hash_password(password, user.salt)
            if hashed_input_password == user.password_hash:
                user.address = address
                user.p2p_port = p2p_port
                return True
        return False

    def email_exists(self, email):
        for user in self.users:
            if user.email == email:
                return True
        return False

    def find_user_by_username(self, username):
        for user in self.users:
            print(user.username)
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
                    if command == "register":
                        self.handle_registration()
                    elif command == "login":
                        self.handle_login()
                    elif command == "privateChat":
                        self.handle_private_chat_request()
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

    def handle_registration(self):
        email = self.receive_message()
        username = self.receive_message()
        password = self.receive_message()
        confirm_password = self.receive_message()
        success = self.user_manager.register_user(email, username, password, confirm_password)
        self.send_message("Registration successful!" if success else "Registration failed!")

    def handle_login(self):
        global num_ports
        global p2p_port

        self.username = self.receive_message()
        password = self.receive_message()
        address = self.socket.getpeername()[0]
        # Send a unique port number
        num_ports += 1
        unique_port = p2p_port + num_ports
        self.send_message(str(unique_port))
        success = self.user_manager.login_user(self.username, password, address, unique_port)
        if success:
            with user_handlers_lock:
                user_handlers[self.username] = self
            self.send_message("Login successful!")
        else:
            self.send_message("Login failed!")


    # def handle_private_chat_request(self):
    #     recipient_username = self.receive_message()
    #     recipient_user = self.user_manager.find_user_by_username(recipient_username)
    #     if recipient_user: #and recipient_user.address and recipient_user.p2p_port:
    #         # self.send_message("P2P_INFO")
    #         self.send_message("P2P_INFO:"+f"{recipient_user.address}:{recipient_user.p2p_port}")
    #         # Send the public key for that recipient
    #         self.send_message(f"{recipient_user.public_key.decode('utf-8')}")
    #         # self.send_message(f"{recipient_user.public_key}")
    #     else:
    #         self.send_message("User does not exist.")

    def handle_private_chat_request(self):
        recipient_username = self.receive_message()
        recipient_user = self.user_manager.find_user_by_username(recipient_username)
        if recipient_user:
            self.send_message(f"P2P_INFO:{recipient_user.address}:{recipient_user.p2p_port}")

            # Generate a random AES key
            aes_key = get_random_bytes(16)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)

            # Encrypt the AES key with RSA
            recipient_key = RSA.import_key(recipient_user.public_key)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            # Send encrypted AES key, AES nonce, and AES tag
            final_message = f"{self.username}:{base64.b64encode(encrypted_aes_key).decode()}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(cipher_aes.tag).decode()}"
            self.send_message(final_message)
        else:
            self.send_message("User does not exist.")



class Server:
    def __init__(self):
        self.user_manager = UserManager()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen(5)

    def run(self):
        print(f"Server listening on {HOST}:{PORT}")
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"Connected by {addr}")
                handler = ClientHandler(client_socket, self.user_manager)
                handler.start()

        except Exception as e:
            print("Server exception:", str(e))

user_handlers = {}
user_handlers_lock = threading.Lock()

if __name__ == "__main__":
    server = Server()
    server.run()



# import socket
# import threading
# import hashlib
# import base64
# import os
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
#
# PORT = 12345
# HOST = 'localhost'
# p2p_port = 12346
# num_ports = 0
#
#
# class User:
#     def __init__(self, email, username, password_hash, salt, public_key, address=None, p2p_port=None):
#         self.email = email
#         self.username = username
#         self.password_hash = password_hash
#         self.salt = salt
#         self.public_key = public_key
#         self.address = address
#         self.p2p_port = p2p_port
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
#
#         user = User(email, username, hashed_password, salt, public_key_pem)
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
#                     else:
#                         self.send_message("Unknown command!")
#             except Exception as e:
#                 print("ClientHandler exception:", str(e))
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
#
#         # Receive key
#         public_key_pem = self.receive_message()
#         public_key = RSA.import_key(public_key_pem)  # public_key_pem.encode('utf-8')
#         success = self.user_manager.register_user(email, username, password, confirm_password, public_key)
#         self.send_message("Registration successful!" if success else "Registration failed!")
#
#     def handle_login(self):
#         global num_ports
#         global p2p_port
#
#         self.username = self.receive_message()
#         password = self.receive_message()
#         address = self.socket.getpeername()[0]
#
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
#             keyDER = base64.b64encode(recipient_user.public_key)
#             self.send_message(keyDER.decode())  # f"PEERPK{recipient_user.public_key.decode('utf-8')}"
#         else:
#             self.send_message("User does not exist.")
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
#     main()

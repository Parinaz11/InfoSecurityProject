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
p2p_port = 12346
num_ports = 1
passphrase = b'123'

class User:
    def __init__(self, email, username, password_hash, salt, address=None, p2p_port=None): # , public_key, private_key
        self.email = email
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        # self.public_key = public_key
        # self.private_key = private_key
        self.address = address
        self.p2p_port = p2p_port

        self.access_level = 1
        self.groups = dict()  # key:group name, value:(access level, certificate)


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
        # key_pair = RSA.generate(2048)
        user = User(email, username, hashed_password, salt)  # , key_pair.publickey(), key_pair
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
                    elif command == "CreatingGroupChat":
                        self.handle_create_group_chat()
                    elif command == "EnterGroups":
                        self.handle_enter_groups()
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
        # send a unique port number
        num_ports += 1
        unique_port = p2p_port + num_ports
        self.send_message(str(unique_port))
        # p2p_port = int(self.receive_message())

        success = self.user_manager.login_user(self.username, password, address, unique_port)
        self.send_message("Login successful!" if success else "Login failed!")

        if success:
            with user_handlers_lock:
                user_handlers[self.username] = self

    def handle_private_chat_request(self):
        recipient_username = self.receive_message()
        recipient_user = self.user_manager.find_user_by_username(recipient_username)
        if recipient_user:
            self.send_message("P2P_INFO")
            self.send_message(f"{recipient_user.address}:{recipient_user.p2p_port}")
        else:
            self.send_message("User does not exist.")

    def handle_enter_groups(self):
        # Receiving the user's id
        user_username = self.receive_message()
        user = self.user_manager.find_user_by_username(user_username)
        # Serialize the dictionary to a JSON string and send it
        self.send_message(json.dumps(user.groups))
        # groups_json = json.dumps(user.groups)
        # # Encode the JSON string to bytes and send it
        # self.socket.sendall(groups_json.encode('utf-8'))


    def handle_create_group_chat(self):
        global num_ports
        global p2p_port

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
        elif group_name in groups:
            # Shouldn't be accepted
            self.send_message("exists")
        else:
            with group_lock:
                groups[group_name] = (group_name, id)
                # Sending a unique group port to this client
                num_ports += 1
                unique_group_port = p2p_port + num_ports
                self.send_message(str(unique_group_port))
                # Create and send a certificate for this user
                cert_pem = generate_certificate(pk, user.username)
                print(f"Generated Certificate: {cert_pem}")
                # Create the group with this certificate
                certificate = cert_pem.decode() # convert to string
                user.groups[group_name] = (1, certificate)  # Access level of admin
                # self.socket.sendall(cert_pem)


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
    groups = {}
    group_lock = threading.Lock()
    main()

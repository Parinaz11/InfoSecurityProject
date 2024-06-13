import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
import base64

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

HOST = 'localhost'
PORT = 12345
server_connection = True


class Client:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))
        self.username = None
        self.key = None
        self.public_key = None
        self.peer_public_key = None

    def run(self):
        try:
            while True:
                print("1. Register")
                print("2. Login")
                print("3. Exit")
                print("4. Private Chat")
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
                else:
                    print("Invalid choice!")
        except Exception as e:
            print("Client exception:", str(e))

    def send_message(self, message):
        self.socket.sendall(message.encode())

    def receive_message(self):
        return self.socket.recv(4096).decode() # 1024

    def receive_keys(self):
        private_key_pem = self.receive_message()
        # print("RECEIVED PRIVATE KEY:", private_key_pem)
        public_key_pem = self.receive_message()
        # print("RECEIVED PUBLIC KEY:", public_key_pem)
        private_key = private_key_pem.encode('utf-8')  # RSA.import_key(private_key_pem)
        public_key = public_key_pem.encode('utf-8')  # RSA.import_key(public_key_pem)
        return private_key, public_key

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

        try:
            self.key, self.public_key = self.receive_keys()
        except Exception as e:
            print("Error for receiving private and public key:", str(e))
        print(self.receive_message())

    def login_user(self):
        self.send_message("login")
        self.username = input("Enter your username: ")
        self.send_message(self.username)
        password = input("Enter your password: ")
        self.send_message(password)

        user_port = self.receive_message()
        try:
            user_port = int(user_port)  # Convert user_port to integer
        except ValueError:
            print("Invalid port number received from the server.")
            return

        p2p_thread = threading.Thread(target=self.start_p2p_server, args=(user_port,), daemon=True)
        p2p_thread.start()

        print(self.receive_message())

    def private_chat(self):
        self.send_message("privateChat")
        recipient_username = input("Enter recipient username: ")
        self.send_message(recipient_username)

        p2p_info_confirm = self.receive_message()
        if p2p_info_confirm.startswith("P2P_INFO"):
            p2p_info = self.receive_message()
            received_public_key_pem = self.receive_message()[6:].strip()
            try:
                self.peer_public_key = RSA.import_key(received_public_key_pem)
                print("Received peer public key.")
            except Exception as e:
                print("Failed to import peer's public key:", str(e))
                return

            print('P2P info', p2p_info)
            address, port = p2p_info.split(":")
            self.p2p_chat(address, int(port))
        else:
            print("Failed to initiate private chat:", p2p_info_confirm)

    def p2p_chat(self, address, port):
        recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        recipient_socket.connect((address, port))

        print("Start typing your messages (type 'exit' to end chat):")
        while True:
            message = input()
            if message == "exit":
                break
            if self.peer_public_key:
                try:
                    recipient_key = self.peer_public_key
                    cipher_rsa = PKCS1_OAEP.new(recipient_key)
                    encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))

                    # print("ERROR FOR SIGNING")
                    # h = SHA256.new(message.encode('utf-8'))
                    # signature = pkcs1_15.new(self.key).sign(h)

                    # Generate AES and HMAC keys
                    aes_key = get_random_bytes(16)
                    hmac_key = get_random_bytes(16)

                    # Encrypt with AES in CTR mode
                    cipher = AES.new(aes_key, AES.MODE_CTR)
                    ciphertext = cipher.encrypt(message.encode('utf-8'))

                    # Compute HMAC
                    hmac = HMAC.new(hmac_key, digestmod=SHA256)
                    hmac.update(cipher.nonce + ciphertext)
                    tag = hmac.digest()

                    # Sign the hashed message with sender's private key
                    h = SHA256.new(cipher.nonce + ciphertext + tag)
                    signature = pkcs1_15.new(self.key).sign(h)


                    final_message = f"{self.username}:{base64.b64encode(encrypted_message).decode()}:{base64.b64encode(signature).decode()}"
                    self.socket.sendall(final_message.encode())
                    print("Message sent successfully!")
                except Exception as e:
                    print(f"Error sending message: {str(e)}")
            else:
                print("Public key of the recipient is not available.")

        print("Ended conversation")
        recipient_socket.close()

    def start_p2p_server(self, p2p_port):
        p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        p2p_socket.bind((HOST, p2p_port))
        p2p_socket.listen(1)
        print(f"P2P server listening on port {p2p_port}")

        while True:
            conn, addr = p2p_socket.accept()
            print(f"Connected to {addr}")
            threading.Thread(target=self.handle_p2p_client, args=(conn,)).start()

    def handle_p2p_client(self, conn):
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break

                username, encrypted_message, signature = data.decode().split(":")
                encrypted_message = base64.b64decode(encrypted_message)
                signature = base64.b64decode(signature)

                cipher_rsa = PKCS1_OAEP.new(self.key)
                message = cipher_rsa.decrypt(encrypted_message).decode('utf-8')

                h = SHA256.new(message.encode())
                try:
                    pkcs1_15.new(self.peer_public_key).verify(h, signature)
                    print(f"Received verified message from {username}: {message}")
                except (ValueError, TypeError):
                    print("The signature is not valid.")


def main():
    client = Client()
    client.run()


if __name__ == "__main__":
    main()

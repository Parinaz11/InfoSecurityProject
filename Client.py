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

class Client:
    def __init__(self):
        global peer_public_key
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))
        self.username = None
        # Generate RSA key pair
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey().export_key()
        # self.peer_key = RSA.generate(2048)
        # peer_public_key = self.peer_key.publickey().export_key()

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
            # # Sign the concatenated nonce, ciphertext, and HMAC tag
            # data_to_sign = cipher_aes.nonce + ciphertext + hmac_tag
            # h = SHA256.new(data_to_sign)
            # signature = pkcs1_15.new(self.key).sign(h)
            #
            # final_message = f"{self.username}:{base64.b64encode(cipher_aes.nonce).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(hmac_tag).decode()}:{base64.b64encode(signature).decode()}"
            # recipient_socket.sendall(final_message.encode())

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

            print("Message sent!")

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
                print("Received peer's public key")

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
                            print("Received message:", decrypted_message.decode('utf-8'))
                        except (ValueError, TypeError) as e:
                            print("Signature verification failed.", str(e))
                    else:
                        print("Peer public key not received. Cannot verify message.")
                else:
                    print("Received message format is incorrect.")
            # else:
            #     # Split the received data into components
            #     parts = message.split(":")
            #     if len(parts) == 6:
            #         sender_username, nonce, ciphertext, tag, hmac_tag, signed_message = parts
            #         nonce = base64.b64decode(nonce)
            #         ciphertext = base64.b64decode(ciphertext)
            #         tag = base64.b64decode(tag)
            #         hmac_tag = base64.b64decode(hmac_tag)
            #         signature = base64.b64decode(signed_message)
            #
            #         # Verify the message
            #         if peer_public_key:
            #             peer_rsa_key = RSA.import_key(peer_public_key)
            #             data_to_verify = nonce + ciphertext + hmac_tag
            #             h = SHA256.new(data_to_verify)
            #             try:
            #                 pkcs1_15.new(peer_rsa_key).verify(h, signature)
            #                 print("Signature is valid.")
            #
            #                 # Encrypt the message with AES
            #                 aes_key = get_random_bytes(16)
            #                 cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            #                 ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
            #
            #                 # Verify HMAC
            #                 hmac = HMAC.new(aes_key, digestmod=SHA256)
            #                 hmac.update(ciphertext + tag)
            #                 hmac.verify(hmac_tag)
            #
            #                 # Decrypt the message
            #                 cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            #                 decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
            #                 print("Received message:", decrypted_message.decode('utf-8'))
            #             except (ValueError, TypeError) as e:
            #                 print("Signature verification failed.", str(e))
            #         else:
            #             print("Peer public key not received. Cannot verify message.")
            #     else:
            #         print("Received message format is incorrect.")

def main():
    client = Client()
    client.run()


if __name__ == "__main__":
    main()



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
#         # Generate RSA key pair
#         self.key = RSA.generate(2048)
#         self.public_key = self.key.publickey().export_key()
#
#         self.peer_key = RSA.generate(2048)
#         peer_public_key = self.peer_key.publickey().export_key()
#
#     def run(self):
#         try:
#             while True:
#                 print("1. Register")
#                 print("2. Login")
#                 print("3. Exit")
#                 print("4. Private Chat")
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
#
#         print(self.receive_message())
#
#     def login_user(self):
#
#         global P2P_PORT
#
#         self.send_message("login")
#         self.username = input("Enter your username: ")
#         self.send_message(self.username)
#         password = input("Enter your password: ")
#         self.send_message(password)
#         # Get the p2p port number which is unique
#         P2P_PORT = int(self.receive_message())
#         p2p_thread = threading.Thread(target=start_p2p_server, daemon=True)
#         p2p_thread.start()
#         # self.send_message(str(P2P_PORT))
#
#         print(self.receive_message())
#
#     def private_chat(self):
#         self.send_message("privateChat")
#         recipient_username = input("Enter recipient username: ")
#         self.send_message(recipient_username)
#
#         p2p_info_confirm = self.receive_message()
#         if p2p_info_confirm.startswith("P2P_INFO"):
#             p2p_info = self.receive_message()
#             print('P2P info', p2p_info)
#             address, port = p2p_info.split(":")
#             self.p2p_chat(address, int(port))
#         else:
#             print("Failed to initiate private chat:", p2p_info_confirm)
#
#     # def p2p_chat(self, address, port):
#     #     recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     #     recipient_socket.connect((address, port))
#     #
#     #     print("Start typing your messages (type 'exit' to end chat):")
#     #     while True:
#     #         message = input()
#     #         if message == "exit":
#     #             break
#     #         recipient_socket.sendall(message.encode())
#     #     recipient_socket.close()
#
#     def p2p_chat(self, address, port):
#         recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         recipient_socket.connect((address, port))
#
#         # Send the public key to the peer
#         recipient_socket.sendall(f"PUBLIC_KEY:{self.public_key.decode()}".encode())
#
#         print("Start typing your messages (type 'exit' to end chat):")
#         while True:
#             message = input()
#             if message == "exit":
#                 break
#
#             # Sign the message
#             # hash_message = SHA256.new(message.encode())
#             # signature = pkcs1_15.new(self.key).sign(hash_message)
#             # signed_message = base64.b64encode(signature).decode()
#
#             # Encrypts the message the public key of other side
#             if peer_public_key is not None:
#                 cipher_rsa = PKCS1_OAEP.new(peer_public_key)
#                 encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
#
#
#                 # Generate AES and HMAC keys
#                 aes_key = get_random_bytes(16)
#                 hmac_key = get_random_bytes(16)
#                 # Encrypt with AES in CTR mode
#                 cipher = AES.new(aes_key, AES.MODE_CTR)
#                 ciphertext = cipher.encrypt(message.encode('utf-8'))
#
#                 # Compute HMAC
#                 hmac = HMAC.new(hmac_key, digestmod=SHA256)
#                 hmac.update(cipher.nonce + ciphertext)
#                 tag = hmac.digest()
#
#                 # Sign the hashed message with sender's private key
#                 h = SHA256.new(cipher.nonce + ciphertext + tag)
#                 signature = pkcs1_15.new(self.key).sign(h)
#
#                 final_message = f"{self.username}:{base64.b64encode(encrypted_message).decode()}:{base64.b64encode(signature).decode()}"
#                 recipient_socket.sendall(final_message.encode())
#
#                 # Send the original message and the signed message
#                 recipient_socket.sendall(f"{message}:{final_message}".encode()) # signed_message
#                 print("Message sent!")
#             else:
#                 print("Peer public key was None")
#
#         recipient_socket.close()
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
#         print(f"Connected to {addr}")
#         threading.Thread(target=handle_p2p_client, args=(conn,)).start()
#
#
# # def handle_p2p_client(conn):
# #     with conn:
# #         while True:
# #             data = conn.recv(1024)
# #             if not data:
# #                 break
# #             print("Received message:", data.decode())
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
#             # if message.startswith("PUBLIC_KEY:"):
#             #     # Receive and set the peer's public key
#             #     peer_public_key_pem = message.split("PUBLIC_KEY:")[1]
#             #     peer_public_key = RSA.import_key(peer_public_key_pem)
#             #     print("Received peer's public key")
#             if message == "exit":
#                 print("EXIT")
#             else:
#                 # Split the received data into the original message and the signed message
#                 original_message, signed_message = message.rsplit(":", 1)
#                 signature = base64.b64decode(signed_message)
#
#                 # Verify the message
#                 if peer_public_key:
#                     hash_message = SHA256.new(original_message.encode())
#                     try:
#                         pkcs1_15.new(peer_public_key).verify(hash_message, signature)
#                         print("Received message:", original_message)
#                         print("Signature is valid.")
#                     except (ValueError, TypeError):
#                         print("Signature verification failed.")
#                 else:
#                     print("Peer public key not received. Cannot verify message.")
#
# def main():
#     client = Client()
#     client.run()
#
#
# if __name__ == "__main__":
#     main()

# ---------------------------------------------------------------------------------------------------------------------

# import socket
# import threading
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.Signature import pkcs1_15
# from Crypto.Hash import SHA256
# from Crypto.Random import get_random_bytes
# from Crypto.Cipher import AES
# import base64
#
# HOST = 'localhost'
# PORT = 12345
#
#
# class Client:
#     def __init__(self):
#         self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.socket.connect((HOST, PORT))
#         self.username = None
#         # Generate RSA key pair
#         self.key = RSA.generate(2048)
#         self.public_key = self.key.publickey().export_key()
#         self.peer_public_key = None
#
#     def run(self):
#         try:
#             while True:
#                 print("1. Register")
#                 print("2. Login")
#                 print("3. Exit")
#                 print("4. Private Chat")
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
#         data = self.socket.recv(1024).decode()
#         return data
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
#
#         print(self.receive_message())
#
#     def login_user(self):
#         self.send_message("login")
#         self.username = input("Enter your username: ")
#         self.send_message(self.username)
#         password = input("Enter your password: ")
#         self.send_message(password)
#
#         # Get the P2P port number which is unique
#         user_port = int(self.receive_message())
#         p2p_thread = threading.Thread(target=self.start_p2p_server, args=(user_port,), daemon=True)
#         p2p_thread.start()
#
#         print(self.receive_message())
#
#     # def private_chat(self):
#     #     self.send_message("privateChat")
#     #     recipient_username = input("Enter recipient username: ")
#     #     self.send_message(recipient_username)
#
#     #     p2p_info_confirm = self.receive_message()
#     #     if p2p_info_confirm == "P2P_INFO":
#     #         p2p_info = self.receive_message()
#     #         received_public_key_pem = self.receive_message()
#     #         try:
#     #             self.peer_public_key = RSA.import_key(received_public_key_pem)
#     #         except Exception as e:
#     #             print("Failed to import peer's public key:", str(e))
#     #             return
#
#     #         address, port = p2p_info.split(":")
#     #         self.p2p_chat(address, int(port))
#     #     else:
#     #         print("Failed to initiate private chat:", p2p_info_confirm)
#
#     # def p2p_chat(self, address, port):
#     #     recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     #     recipient_socket.connect((address, port))
#
#     #     print("Start typing your messages (type 'exit' to end chat):")
#     #     while True:
#     #         message = input()
#
#     #         if self.peer_public_key is not None:
#     #             cipher_rsa = PKCS1_OAEP.new(self.peer_public_key)
#     #             encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
#
#     #             # Sign the message
#     #             h = SHA256.new(message.encode('utf-8'))
#     #             signature = pkcs1_15.new(self.key).sign(h)
#
#     #             # Combine username, encrypted message and signature
#     #             final_message = f"{self.username}:{base64.b64encode(encrypted_message).decode()}:{base64.b64encode(signature).decode()}"
#     #             print(f"sending encrypted message :{final_message}")
#     #             recipient_socket.sendall(final_message.encode())
#
#     #         else:
#     #             print("public key of recipent is not available")
#
#     #         if message == "exit":
#     #             break
#
#     #     print("Ended conversation")
#     #     recipient_socket.close()
#
#     def private_chat(self):
#         self.send_message("privateChat")
#         recipient_username = input("Enter recipient username: ")
#         self.send_message(recipient_username)
#
#         p2p_info_confirm = self.receive_message()
#         if p2p_info_confirm.startswith("P2P_INFO"):
#             parts = p2p_info_confirm.split(":")
#             if len(parts) >= 2:
#                 p2p_info = parts[0]
#                 address = parts[1]
#                 port = parts[2]
#                 # p2p_info = p2p_info_confirm.split(":")[1]  # Extracting address:port info
#                 self.peer_public_key = self.receive_message().encode('utf-8')  # Receive peer's public key
#
#                 print('P2P info', p2p_info)
#                 # address, port = p2p_info.split(":")
#                 self.p2p_chat(address, int(port))
#             else:
#                 print("invalid P2P_INFO format recieved, ", p2p_info_confirm)
#         else:
#             print("Failed to initiate private chat:", p2p_info_confirm)
#
#     def p2p_chat(self, address, port):
#         recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         recipient_socket.connect((address, port))
#
#         print("Start typing your messages (type 'exit' to end chat):")
#         while True:
#             message = input()
#
#             print("PEER PUBLIC KEY NOT NONE: " + self.peer_public_key)
#             if self.peer_public_key is not None:
#
#                 # aes
#                 aes_key = get_random_bytes(16)
#                 cipher_aes = AES.new(aes_key, AES.MODE_EAX)
#
#                 ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
#
#                 # recipient_key = RSA.import_key(self.peer_public_key)
#                 # cipher_rsa = PKCS1_OAEP.new(recipient_key)
#                 # encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
#
#                 recipient_key = self.peer_public_key.encode('utf-8')  #  RSA.import_key(self.peer_public_key)
#                 cipher_rsa = PKCS1_OAEP.new(recipient_key)
#                 encrypted_aes_key = cipher_rsa.encrypt(aes_key)
#
#                 # Sign the message
#                 h = SHA256.new(message.encode('utf-8'))
#                 signature = pkcs1_15.new(self.key).sign(h)
#
#                 # Combine username, encrypted message and signature
#                 # final_message = f"{self.username}:{base64.b64encode(encrypted_message).decode()}:{base64.b64encode(signature).decode()}"
#                 final_message = f"{self.username}:{base64.b64encode(encrypted_aes_key).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}"
#
#                 print(f"no encode:", final_message)
#                 print(f"encode:", final_message.encode())
#                 recipient_socket.sendall(final_message.encode())
#             else:
#                 print("Public key of the recipient is not available.")
#
#             if message.lower() == "exit":
#                 break
#
#         print("Ended conversation")
#         recipient_socket.close()
#
#     # def p2p_chat(self, address, port):
#     #     recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     #     recipient_socket.connect((address, port))
#     #     print("Connected to address", address, "and port", port)
#     #
#     #     print("Start typing your messages (type 'exit' to end chat):")
#     #     while True:
#     #         message = input()
#     #         if message == "exit":
#     #             break
#     #         elif self.peer_public_key:
#     #             try:
#     #                 # Encrypts the message the public key of other side
#     #                 recipient_key = self.peer_public_key
#     #                 cipher_rsa = PKCS1_OAEP.new(recipient_key)
#     #                 encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
#     #
#     #                 # print("ERROR FOR SIGNING")
#     #                 # h = SHA256.new(message.encode('utf-8'))
#     #                 # signature = pkcs1_15.new(self.key).sign(h)
#     #
#     #                 # Signs the message using the user's private key
#     #                 # Generate AES and HMAC keys
#     #                 aes_key = get_random_bytes(16)
#     #                 hmac_key = get_random_bytes(16)
#     #
#     #                 # Encrypt with AES in CTR mode
#     #                 cipher = AES.new(aes_key, AES.MODE_CTR)
#     #                 ciphertext = cipher.encrypt(message.encode('utf-8'))
#     #
#     #                 # Compute HMAC
#     #                 hmac = HMAC.new(hmac_key, digestmod=SHA256)
#     #                 hmac.update(cipher.nonce + ciphertext)
#     #                 tag = hmac.digest()
#     #
#     #                 # Sign the hashed message with sender's private key
#     #                 h = SHA256.new(cipher.nonce + ciphertext + tag)
#     #                 signature = pkcs1_15.new(self.key).sign(h)
#     #
#     #                 final_message = f"{self.username}:{base64.b64encode(encrypted_message).decode()}:{base64.b64encode(signature).decode()}"
#     #                 recipient_socket.sendall(final_message.encode())
#     #                 print("Message sent successfully!")
#     #             except Exception as e:
#     #                 print(f"Error sending message: {str(e)}")
#     #         else:
#     #             print("Public key of the recipient is not available.")
#     #
#     #     print("Ended conversation")
#     #     recipient_socket.close()
#
#     def start_p2p_server(self, P2P_PORT):
#         p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         p2p_socket.bind((HOST, P2P_PORT))
#         p2p_socket.listen(1)
#         print(f"P2P server listening on port {P2P_PORT}")
#
#         while True:
#             conn, addr = p2p_socket.accept()
#             print(f"Connected to {addr}")
#             threading.Thread(target=self.handle_p2p_client, args=(conn,)).start()
#
#     # def handle_p2p_client(self, conn):
#     #     with conn:
#     #         while True:
#     #             data = conn.recv(1024)
#     #             if not data:
#     #                 break
#
#     #             print(f"Received data: {data.decode()}")
#
#     #             try:
#     #                 parts = data.decode().split(":")
#     #                 if len(parts) != 3:
#     #                     print("Invalid message format")
#     #                     continue
#
#     #                 # username = parts[0]
#     #                 # encrypted_message = base64.b64decode(parts[1].encode('utf-8'))
#     #                 # signature = base64.b64decode(parts[2])
#     #                 username, encrypted_message, signature = data.decode().split(":")
#     #                 encrypted_message = base64.b64decode(encrypted_message.encode('utf-8')) # ADDED ENCODE
#     #                 signature = base64.b64decode(signature)
#     #                 # username, encrypted_message_b64, signature_b64 = parts
#     #                 # encrypted_message = base64.b64decode(encrypted_message_b64.encode())
#     #                 # signature = base64.b64decode(signature_b64.encode())
#
#     #                 # Decrypt the message
#     #                 try:
#     #                     cipher_rsa = PKCS1_OAEP.new(self.key)
#     #                     message = cipher_rsa.decrypt(encrypted_message).decode('utf-8')
#     #                     print(f"Decrypted message: {message}")
#
#     #                     # Verify the signature
#     #                     h = SHA256.new(message.encode('utf-8'))
#     #                     peer_public_key = RSA.import_key(self.peer_public_key)
#     #                     try:
#     #                         pkcs1_15.new(RSA.import_key(self.peer_public_key)).verify(h, signature)
#     #                         #pkcs1_15.new(peer_public_key).verify(h, signature)
#     #                         print(f"Signature verified for message from {username}: {message}")
#     #                     except (ValueError, TypeError):
#     #                         print("The signature is not valid.")
#     #                 except ValueError as e:
#     #                     print(f"Decryption failed: {str(e)}")
#     #             except Exception as e:
#     #                 print(f"Error processing message: {str(e)}")
#     def handle_p2p_client(self, conn):
#         with conn:
#             while True:
#                 # data = conn.recv(4096)
#                 # if not data:
#                 #     break
#                 #
#                 # try:
#                 #     parts = data.decode().split(":")
#                 #     if len(parts) != 4:
#                 #         print("Invalid message format")
#                 #         continue
#                 #
#                 #     username, encrypted_aes_key_b64, nonce_b64, tag_b64 = parts
#                 #     encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64.encode())
#                 #     nonce = base64.b64decode(nonce_b64.encode())
#                 #     tag = base64.b64decode(tag_b64.encode())
#                 #
#                 #     # Decrypt the AES key with RSA
#                 #     cipher_rsa = PKCS1_OAEP.new(self.key)
#                 #     aes_key = cipher_rsa.decrypt(encrypted_aes_key)
#                 #
#                 #     # Decrypt the message with AES
#                 #     cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
#                 #     decrypted_message = cipher_aes.decrypt_and_verify(data[len(username) + 1:].encode(), tag).decode()
#                 #
#                 #     print(f"Received verified message from {username}: {decrypted_message}")
#                 #
#                 # except Exception as e:
#                 #     print(f"Error processing message: {str(e)}")
#
#                 data = conn.recv(1024)
#                 if not data:
#                     break
#                 print('I THINK HERE NEEDS CONFIGURE')
#                 username, encrypted_message, signature = data.decode().split(":")
#                 encrypted_message = base64.b64decode(encrypted_message)
#                 signature = base64.b64decode(signature)
#
#                 cipher_rsa = PKCS1_OAEP.new(self.key)
#                 message = cipher_rsa.decrypt(encrypted_message).decode('utf-8')
#
#                 h = SHA256.new(message.encode())
#                 try:
#                     pkcs1_15.new(self.peer_public_key).verify(h, signature)
#                     print(f"Received verified message from {username}: {message}")
#                 except (ValueError, TypeError):
#                     print("The signature is not valid.")
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
#
# #
# # import socket
# # import threading
# # from Crypto.PublicKey import RSA
# # from Crypto.Cipher import PKCS1_OAEP
# # from Crypto.Signature import pkcs1_15
# # import base64
# #
# # from Crypto.Cipher import AES
# # from Crypto.Hash import HMAC, SHA256
# # from Crypto.Random import get_random_bytes
# #
# # HOST = 'localhost'
# # PORT = 12345
# # server_connection = True
# #
# #
# # class Client:
# #     def __init__(self):
# #         self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #         self.socket.connect((HOST, PORT))
# #         self.username = None
# #         self.key = None
# #         self.public_key = None
# #         self.peer_public_key = None
# #
# #     def run(self):
# #         try:
# #             while True:
# #                 print("1. Register")
# #                 print("2. Login")
# #                 print("3. Exit")
# #                 print("4. Private Chat")
# #                 choice = input("Enter your choice: ")
# #
# #                 if choice == "1":
# #                     self.register_user()
# #                 elif choice == "2":
# #                     self.login_user()
# #                 elif choice == "3":
# #                     print("Exiting...")
# #                     break
# #                 elif choice == "4":
# #                     self.private_chat()
# #                 else:
# #                     print("Invalid choice!")
# #         except Exception as e:
# #             print("Client exception:", str(e))
# #
# #     def send_message(self, message):
# #         self.socket.sendall(message.encode())
# #
# #     def receive_message(self):
# #         return self.socket.recv(1024).decode()
# #
# #     # def receive_keys(self):
# #     #     private_key_pem = self.receive_message()
# #     #     # print("RECEIVED PRIVATE KEY:", private_key_pem)
# #     #     public_key_pem = self.receive_message()
# #     #     # print("RECEIVED PUBLIC KEY:", public_key_pem)
# #     #     private_key = private_key_pem.encode('utf-8')  # RSA.import_key(private_key_pem)
# #     #     public_key = public_key_pem.encode('utf-8')  # RSA.import_key(public_key_pem)
# #     #     return private_key, public_key
# #
# #     def register_user(self):
# #         self.send_message("register")
# #         email = input("Enter your email: ")
# #         self.send_message(email)
# #         username = input("Enter your username: ")
# #         self.send_message(username)
# #         password = input("Enter your password: ")
# #         self.send_message(password)
# #         confirm_password = input("Confirm your password: ")
# #         self.send_message(confirm_password)
# #
# #         # Generate keys and sent the public one
# #         key_pair = RSA.generate(2048)
# #         self.public_key = key_pair.publickey().export_key()
# #         self.key = key_pair.export_key()
# #         print("PUBLIC KEY: " + self.public_key.decode('utf-8'))
# #         self.send_message(self.public_key.decode('utf-8'))
# #
# #         print(self.receive_message())  # Whether it was successful or not
# #
# #     def login_user(self):
# #         self.send_message("login")
# #         self.username = input("Enter your username: ")
# #         self.send_message(self.username)
# #         password = input("Enter your password: ")
# #         self.send_message(password)
# #
# #         user_port = self.receive_message()
# #         try:
# #             user_port = int(user_port)  # Convert user_port to integer
# #         except ValueError:
# #             print("Invalid port number received from the server.")
# #             return
# #
# #         p2p_thread = threading.Thread(target=self.start_p2p_server, args=(user_port,), daemon=True)
# #         p2p_thread.start()
# #
# #         print(self.receive_message())
# #
# #     def private_chat(self):
# #         self.send_message("privateChat")
# #         recipient_username = input("Enter recipient username: ")
# #         self.send_message(recipient_username)
# #
# #         confirm = self.receive_message()
# #         if confirm.startswith("P2P_INFO"):
# #             p2p_info = self.receive_message()
# #             print('P2P INFO IS:', p2p_info)
# #             received_public_key_pem = self.receive_message()  # [6:].strip()
# #             print("THE KEY IS", received_public_key_pem)
# #             try:
# #                 self.peer_public_key = received_public_key_pem.encode('utf-8')  # RSA.import_key(received_public_key_pem)
# #                 print("Received peer public key.")
# #             except Exception as e:
# #                 print("Failed to import peer's public key:", str(e))
# #                 return
# #
# #             print('P2P info', p2p_info)
# #             address, port = p2p_info.split(":")
# #             self.p2p_chat(address, int(port))
# #         else:
# #             print("Failed to initiate private chat:", confirm)
# #
# #     def p2p_chat(self, address, port):
# #         recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #         recipient_socket.connect((address, port))
# #         print("Connected to address", address, "and port", port)
# #
# #         print("Start typing your messages (type 'exit' to end chat):")
# #         while True:
# #             message = input()
# #             if message == "exit":
# #                 break
# #             elif self.peer_public_key:
# #                 try:
# #                     # Encrypts the message the public key of other side
# #                     recipient_key = self.peer_public_key
# #                     cipher_rsa = PKCS1_OAEP.new(recipient_key)
# #                     encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
# #
# #                     # print("ERROR FOR SIGNING")
# #                     # h = SHA256.new(message.encode('utf-8'))
# #                     # signature = pkcs1_15.new(self.key).sign(h)
# #
# #                     # Signs the message using the user's private key
# #                     # Generate AES and HMAC keys
# #                     aes_key = get_random_bytes(16)
# #                     hmac_key = get_random_bytes(16)
# #
# #                     # Encrypt with AES in CTR mode
# #                     cipher = AES.new(aes_key, AES.MODE_CTR)
# #                     ciphertext = cipher.encrypt(message.encode('utf-8'))
# #
# #                     # Compute HMAC
# #                     hmac = HMAC.new(hmac_key, digestmod=SHA256)
# #                     hmac.update(cipher.nonce + ciphertext)
# #                     tag = hmac.digest()
# #
# #                     # Sign the hashed message with sender's private key
# #                     h = SHA256.new(cipher.nonce + ciphertext + tag)
# #                     signature = pkcs1_15.new(self.key).sign(h)
# #
# #                     final_message = f"{self.username}:{base64.b64encode(encrypted_message).decode()}:{base64.b64encode(signature).decode()}"
# #                     recipient_socket.sendall(final_message.encode())
# #                     print("Message sent successfully!")
# #                 except Exception as e:
# #                     print(f"Error sending message: {str(e)}")
# #             else:
# #                 print("Public key of the recipient is not available.")
# #
# #         print("Ended conversation")
# #         recipient_socket.close()
# #
# #     def start_p2p_server(self, p2p_port):
# #         p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #         p2p_socket.bind((HOST, p2p_port))
# #         p2p_socket.listen(1)
# #         print(f"P2P server listening on port {p2p_port}")
# #
# #         while True:
# #             conn, addr = p2p_socket.accept()
# #             print(f"Connected to {addr}")
# #             threading.Thread(target=self.handle_p2p_client, args=(conn,)).start()
# #
# #     def handle_p2p_client(self, conn):
# #         with conn:
# #             while True:
# #                 data = conn.recv(1024)
# #                 if not data:
# #                     break
# #                 print('I THINK HERE NEEDS CONFIGURE')
# #                 username, encrypted_message, signature = data.decode().split(":")
# #                 encrypted_message = base64.b64decode(encrypted_message)
# #                 signature = base64.b64decode(signature)
# #
# #                 cipher_rsa = PKCS1_OAEP.new(self.key)
# #                 message = cipher_rsa.decrypt(encrypted_message).decode('utf-8')
# #
# #                 h = SHA256.new(message.encode())
# #                 try:
# #                     pkcs1_15.new(self.peer_public_key).verify(h, signature)
# #                     print(f"Received verified message from {username}: {message}")
# #                 except (ValueError, TypeError):
# #                     print("The signature is not valid.")
# #
# #
# # def main():
# #     client = Client()
# #     client.run()
# #
# #
# # if __name__ == "__main__":
# #     main()

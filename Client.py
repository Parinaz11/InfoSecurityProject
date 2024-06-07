import socket
import threading
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = 'localhost'
PORT = 12345
P2P_PORT = 12346


class Client:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))
        self.username = None

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
            print('P2PPPP info', p2p_info)
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
            recipient_socket.sendall(message.encode())
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
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print("Received message:", data.decode())


def main():
    client = Client()
    client.run()


if __name__ == "__main__":
    main()

import socket
import threading
import hashlib
from rsa import RSA

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.rsa = RSA()

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        public_key, private_key = self.rsa.generate_keys()

        # exchange public keys
        self.s.recv(1024)
        self.s.send(f"{public_key[0]}:{public_key[1]}".encode())

        # receive the encrypted secret key
        encrypted_secret = int(self.s.recv(1024).decode())

        secret = self.rsa.decrypt(encrypted_secret, private_key)
        self.secret_bytes = secret.to_bytes(32, 'big')


        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def stream_cipher(self, data):
        result = []
        for i, byte in enumerate(data):
            result.append(byte ^ self.secret_bytes[i % len(self.secret_bytes)])
        return bytes(result)

    def read_handler(self):
        while True:
            message = self.s.recv(4096).decode()

            # decrypt message with the secrete key

            msg_hash, encrypted_hex = message.split(":", 1)
            decrypted = self.stream_cipher(bytes.fromhex(encrypted_hex))
            message = decrypted.decode()

            if hashlib.sha256(message.encode()).hexdigest() != msg_hash:
                print("Повідомлення змінено! Можлива атака")
            else:
                print(message)

    def write_handler(self):
        while True:
            message = input()

            # encrypt message with the secrete key
            msg_hash = hashlib.sha256(message.encode()).hexdigest()
            encrypted = self.stream_cipher(message.encode()).hex()
            self.s.send(f"{msg_hash}:{encrypted}".encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()

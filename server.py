import socket
import threading
import random
import hashlib
from rsa import RSA

class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.rsa = RSA()
        self.secret = random.getrandbits(256)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...
        public_key,private_key = self.rsa.generate_keys()

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.username_lookup[c] = username

            # send public key to the client

            c.send(f"{public_key[0]}:{public_key[1]}".encode())

            # encrypt the secret with the clients public key

            client_key = c.recv(1024).decode()
            e,n = map(int, client_key.split(":"))
            encrypted_secret = self.rsa.encrypt(self.secret, (e,n))

            # send the encrypted secret to a client

            c.send(str(encrypted_secret).encode())

            self.clients.append(c)
            self.broadcast(f'new person has joined: {username}')

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def stream_cipher(self, data):
        key = self.secret.to_bytes(32, 'big')
        result = []
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

    def broadcast(self, msg: str):
        for client in self.clients:

            # encrypt the message
            encrypted = self.stream_cipher(msg.encode()).hex()
            msg_hash = hashlib.sha256(msg.encode()).hexdigest()
            client.send(f"{msg_hash}:{encrypted}".encode())

    def handle_client(self, c: socket, addr):
        while True:
            msg = c.recv(4096)

            for client in self.clients:
                if client != c:
                    client.send(msg)

if __name__ == "__main__":
    s = Server(9001)
    s.start()

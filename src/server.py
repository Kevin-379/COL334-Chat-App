import socket
import threading
import string
import constants
import sys


class Client:
    def __init__(
        self,
        client_send: socket.socket,
        addr_send,
        client_recv: socket.socket,
        addr_recv,
    ):
        self.username = ""
        self.socket_send = client_send
        self.socket_recv = client_recv
        self.addr_send = addr_send
        self.addr_recv = addr_recv


class Server:
    def __init__(self, ip=None, port=None):
        self.HEADER_LENGTH = constants.HEADER_LENGTH
        self.SERVER = (
            ip if ip is not None else socket.gethostbyname(socket.gethostname())
        )
        self.PORT = port if port is not None else constants.PORT
        self.ADDR = (self.SERVER, self.PORT)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(self.ADDR)
        self.threads: list[threading.Thread] = []
        self.clients: dict[str, Client] = {}

    @staticmethod
    def send(message: str, sock: socket.socket):
        encoded_message = message.encode()
        sock.send(encoded_message)

    def start(self):
        print(f"Starting server on {self.SERVER}:{self.PORT}")
        self.server.listen()

        while True:
            client_send, addr_send = self.server.accept()
            client_recv, addr_recv = self.server.accept()
            client = Client(client_send, addr_send, client_recv, addr_recv)
            thread = threading.Thread(target=self.handle_client, args=(client,))
            thread.start()
            self.threads.append(thread)

        for thread in self.threads:
            thread.join()

    def _receive(self, sock: socket.socket):
        message = sock.recv(self.HEADER_LENGTH).decode()
        if not message:
            return None

        if len(message) == self.HEADER_LENGTH:
            if not message.startswith(constants.SEND):
                return message

            idx1 = message.find("\n")
            if idx1 == -1:
                return message

            idx2 = message.find("\n", idx1 + 1)
            if idx2 == -1:
                return message

            if (
                message[idx1 + 1 : idx1 + 1 + len(constants.CONTENT_LENGTH)]
                != constants.CONTENT_LENGTH
            ):
                return message

            content_length = message[idx1 + 1 + len(constants.CONTENT_LENGTH) : idx2]
            try:
                size = int(content_length) - 1024 + idx2 + 2
            except ValueError:
                return message

            while size > 0:
                temp_message = sock.recv(self.HEADER_LENGTH).decode()
                message += temp_message
                size -= len(temp_message)

        return message

    def handle_client(self, client: Client):
        print(f"Received connection {client.addr_send}")
        print(f"Received connection {client.addr_recv}")
        connected = self.register_client(client)

        while connected:
            message = self._receive(client.socket_send)
            if message is None:
                break

            # SEND [recipient username]\nContent-length: [length]\n\n[data]
            if message.startswith(constants.SEND):
                idx = message.find("\n")  # End of first line
                if idx == -1:
                    self.send(constants.ERROR_103, client.socket_recv)
                    break

                recipient = message[len(constants.SEND) : idx]
                message = message[idx + 1 :]  # Rest of message

                if not message.startswith(constants.CONTENT_LENGTH):
                    self.send(constants.ERROR_103, client.socket_recv)
                    break

                idx = message.find("\n")  # End of second line
                if idx == -1 or message[idx + 1] != "\n":
                    self.send(constants.ERROR_103, client.socket_recv)
                    break

                length = message[len(constants.CONTENT_LENGTH) : idx]  # content length
                try:
                    length = int(length)
                except ValueError:
                    self.send(constants.ERROR_103, client.socket_recv)
                    break

                message = message[idx + 2 :]  # Rest of message
                if length != len(message):
                    self.send(constants.ERROR_103, client.socket_recv)
                    break

                if message == "exit":
                    self.send("exit", client.socket_recv)
                    break

                if recipient == constants.ALL:  # Send to all
                    send_message = f"{constants.FORWARD}{client.username}\n{constants.CONTENT_LENGTH}{length}\n\n{message}"
                    for recipient in self.clients:
                        if recipient == client.username:
                            continue  # Don't send to self
                        self.send(send_message, self.clients[recipient].socket_recv)

                    sent = True  # Flag to check if everyone received correctly
                    for recipient in self.clients:
                        if recipient == client.username:
                            continue
                        # Acknowledgement
                        message = self._receive(self.clients[recipient].socket_recv)
                        if not (
                            message is not None
                            and message.startswith(constants.RECEIVED)
                            and message.endswith("\n\n")
                            and message[len(constants.RECEIVED) : -2] == client.username
                        ):  # Nack
                            sent = False

                    if sent:  # Message sent correctly
                        self.send(
                            f"{constants.SEND}{constants.ALL}\n\n",
                            client.socket_recv,
                        )
                    else:
                        self.send(constants.ERROR_102, client.socket_recv)

                    continue

                if recipient not in self.clients:
                    self.send(constants.ERROR_102, client.socket_recv)
                    continue

                # Send to recipient
                send_message = f"{constants.FORWARD}{client.username}\n{constants.CONTENT_LENGTH}{length}\n\n{message}"
                self.send(send_message, self.clients[recipient].socket_recv)

                # Acknowledgement
                message = self._receive(self.clients[recipient].socket_recv)
                if (
                    message is not None
                    and message.startswith(constants.RECEIVED)
                    and message.endswith("\n\n")
                    and message[len(constants.RECEIVED) : -2] == client.username
                ):  # Nack
                    self.send(f"{constants.SEND}{recipient}\n\n", client.socket_recv)
                else:
                    self.send(constants.ERROR_102, client.socket_recv)
                continue

            # Cannot handle message
            break

        # Close connection
        client.socket_send.close()
        client.socket_recv.close()
        if client.username in self.clients:
            del self.clients[client.username]  # Remove client

    def register_client(self, client: Client):
        message = self._receive(client.socket_send)
        if message is None:
            return False

        # REGISTER TOSEND [username]\n\n
        if not (
            message.startswith(constants.REGISTER_SEND) and message.endswith("\n\n")
        ):
            self.send(constants.ERROR_103, client.socket_send)
            return False

        client.username = message[len(constants.REGISTER_SEND) : -2]
        # Invalid username
        if client.username in self.clients or not self._valid_username(client.username):
            self.send(constants.ERROR_100, client.socket_send)
            return False

        self.send(
            f"{constants.REGISTERED_SEND}{client.username}\n\n", client.socket_send
        )

        message = self._receive(client.socket_recv)
        if message is None:
            return False

        # REGISTER TORECV [username]\n\n
        if not (
            message.startswith(constants.REGISTER_RECV) and message.endswith("\n\n")
        ):
            self.send(constants.ERROR_101, client.socket_recv)
            return False

        username = message[len(constants.REGISTER_RECV) : -2]
        # Username mismatch
        if username != client.username:
            self.send(constants.ERROR_100, client.socket_recv)
            return False

        self.send(
            f"{constants.REGISTERED_RECV}{client.username}\n\n", client.socket_recv
        )
        self.clients[client.username] = client
        return True

    @staticmethod
    def _valid_username(username: str):
        # Validate username
        valid = string.ascii_letters + string.digits  # "A...Za...z0...9"
        for char in username:
            if char not in valid:  # Invalid character
                return False
        return True


def main():
    ip, port = None, None
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    if len(sys.argv) > 2:
        port = sys.argv[2]
        try:
            port = int(port)
        except ValueError:
            print("Warning: Port must be integer")
            port = None
    server = Server(ip, port)
    server.start()


if __name__ == "__main__":
    main()

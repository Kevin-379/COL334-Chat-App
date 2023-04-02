import socket
import constants
import sys
import threading


class User:
    def __init__(self, username: str, ip=None, port=None):
        self.HEADER_LENGTH = constants.HEADER_LENGTH
        self.username = username
        self.SERVER = (
            ip if ip is not None else socket.gethostbyname(socket.gethostname())
        )
        self.PORT = port if port is not None else constants.PORT
        self.ADDR = (self.SERVER, self.PORT)
        self.user_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.user_recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = True

    def start(self):
        self.user_send.connect(self.ADDR)
        self.user_recv.connect(self.ADDR)
        if self.register():
            self.receive()
        self.connected = False

    @staticmethod
    def send(message: str, sock: socket.socket):
        encoded_message = message.encode()
        sock.send(encoded_message)

    def _receive(self, sock: socket.socket):
        message = sock.recv(self.HEADER_LENGTH).decode()
        if not message:
            return None

        if len(message) == self.HEADER_LENGTH:
            if not message.startswith(constants.FORWARD):
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

    def _register(self, send_message: str, recv_message: str, sock: socket.socket):
        self.send(send_message, sock)

        message = self._receive(sock)
        if message is not None and message == recv_message:
            return True

        return False

    def register(self):
        send_message = f"{constants.REGISTER_SEND}{self.username}\n\n"
        send_response = f"{constants.REGISTERED_SEND}{self.username}\n\n"
        recv_message = f"{constants.REGISTER_RECV}{self.username}\n\n"
        recv_response = f"{constants.REGISTERED_RECV}{self.username}\n\n"
        return self._register(
            send_message, send_response, self.user_send
        ) and self._register(recv_message, recv_response, self.user_recv)

    def receive(self):
        while True:
            message = self._receive(self.user_recv)
            if message is None:
                break

            if message == "exit":
                break

            # SEND [recipient username]\n\n
            if message.startswith(constants.SEND) and message.endswith("\n\n"):
                recipient = message[len(constants.SEND) : -2]
                print(f"\rmessage sent to {recipient}\n> ", end="")
                continue

            # FORWARD [sender username]\nContent-length: [length]\n\n[message]
            if message.startswith(constants.FORWARD):
                idx = message.find("\n")
                if idx == -1:
                    self.send(constants.ERROR_103, self.user_recv)
                    break

                sender = message[len(constants.FORWARD) : idx]
                message = message[idx + 1 :]

                if not message.startswith(constants.CONTENT_LENGTH):
                    self.send(constants.ERROR_103, self.user_recv)
                    break

                idx = message.find("\n")
                if idx == -1 or message[idx + 1] != "\n":
                    self.send(constants.ERROR_103, self.user_recv)
                    break

                length = message[len(constants.CONTENT_LENGTH) : idx]
                message = message[idx + 2 :]
                try:
                    length = int(length)
                except ValueError:
                    self.send(constants.ERROR_103, self.user_recv)
                    break

                if length != len(message):
                    self.send(constants.ERROR_103, self.user_recv)
                    break

                print(f"\r@{sender}: {message}\n> ", end="")
                self.send(f"{constants.RECEIVED}{sender}\n\n", self.user_recv)
                continue

            # Unable to send
            if message == constants.ERROR_102:
                print(f"\rError 102: Unable to send\n> ", end="")
                continue

            break


def main():
    if len(sys.argv) == 1:
        print("ERROR: username not provided")
        return
    username = sys.argv[1]
    ip, port = None, None
    if len(sys.argv) > 2:
        ip = sys.argv[2]
    if len(sys.argv) > 3:
        port = sys.argv[3]
        try:
            port = int(port)
        except ValueError:
            print("Warning: Port must be integer")
            port = None

    user = User(username, ip, port)
    thread = threading.Thread(target=user.start)
    thread.start()

    while user.connected:
        data = input("\r> ")
        idx = data.find(" ")
        if (not data.startswith("@")) or idx == -1:
            print("Error: Message should be of the format: @[recipient] [message]")
            continue
        recipient = data[1:idx]
        data = data[idx + 1 :]
        message = f"{constants.SEND}{recipient}\n{constants.CONTENT_LENGTH}{len(data)}\n\n{data}"
        user.send(message, user.user_send)
        if data == "exit":
            break

    thread.join()


if __name__ == "__main__":
    main()

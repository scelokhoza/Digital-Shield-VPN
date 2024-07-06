import socket
import ssl
import threading


class VPNServer:
    def __init__(self, server_address='0.0.0.0', port=8080, certfile='server.crt', keyfile='server.key'):
        self.server_address = server_address
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.certfile = certfile
        self.keyfile = keyfile

    def start_vpn(self):
        try:
            self.server_socket.bind((self.server_address, self.port))
            self.server_socket.listen(5)
            print(f"Server started on {self.server_address}:{self.port}")

            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connection from {client_address}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()

        except PermissionError as e:
            print(f"Permission denied: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.server_socket.close()

    def handle_client(self, client_socket):
        try:
            ssl_client_socket = ssl.wrap_socket(client_socket,
                                                server_side=True,
                                                certfile=self.certfile,
                                                keyfile=self.keyfile,
                                                ssl_version=ssl.PROTOCOL_TLS)
            # Handle the client connection
            data = ssl_client_socket.recv(1024)
            print(f"Received data: {data}")
            ssl_client_socket.sendall(b'Hello from server')
        except ssl.SSLError as e:
            print(f"SSL error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            ssl_client_socket.close()


if __name__ == '__main__':
    server = VPNServer()
    server.start_vpn()

    
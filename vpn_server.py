import socket
import ssl
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

class VPNServer:
    def __init__(self, server_address='0.0.0.0', port=8080, certfile='server.crt', keyfile='server.key'):
        self.server_address = server_address
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.certfile = certfile
        self.keyfile = keyfile

        # Generate RSA keys for the server
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        # Serialize public key to send to the client
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

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
            # Send the server's public key to the client
            ssl_client_socket.sendall(self.public_pem)

            # Receive the encrypted symmetric key from the client
            encrypted_symmetric_key = ssl_client_socket.recv(4096)
            symmetric_key = self.private_key.decrypt(
                encrypted_symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            cipher = Fernet(symmetric_key)

            while True:
                encrypted_data = ssl_client_socket.recv(4096)
                if not encrypted_data:
                    break

                data = cipher.decrypt(encrypted_data)
                response = self.forward_to_destination(data)
                encrypted_response = cipher.encrypt(response)
                ssl_client_socket.sendall(encrypted_response)

        except ssl.SSLError as e:
            print(f"SSL error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            ssl_client_socket.close()

    def forward_to_destination(self, data):
        # Placeholder: Modify this method to forward data to the appropriate destination
        destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        destination_socket.connect(('destination_address', 80))
        destination_socket.sendall(data)
        response = destination_socket.recv(4096)
        destination_socket.close()
        return response

if __name__ == '__main__':
    server = VPNServer()
    server.start_vpn()

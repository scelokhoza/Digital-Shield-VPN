import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet


class VPNClient:
    def __init__(self, server_address='0.0.0.0', port=8080, server_hostname='YourName'):
        self.server_address = server_address
        self.port = port
        self.server_hostname = server_hostname
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.create_default_context()

        # Disable hostname verification and certificate verification for self-signed certificates
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        self.secure_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.server_hostname)
        self.symmetric_key = Fernet.generate_key()
        self.cipher = Fernet(self.symmetric_key)

    def connect_to_vpn(self):
        try:
            self.secure_socket.connect((self.server_address, self.port))
            print(f"Connected to VPN server at {self.server_address}:{self.port}")

            # Receive server's public key
            server_public_key_pem = self.secure_socket.recv(4096)
            server_public_key = serialization.load_pem_public_key(server_public_key_pem)

            # Encrypt the symmetric key with the server's public key and send it
            encrypted_symmetric_key = server_public_key.encrypt(
                self.symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.secure_socket.sendall(encrypted_symmetric_key)

            while True:
                url = input("Enter the URL to fetch: ")
                encrypted_message = self.cipher.encrypt(url.encode())
                self.secure_socket.sendall(encrypted_message)

                encrypted_response = self.secure_socket.recv(4096)
                response = self.cipher.decrypt(encrypted_response)
                print(f"Received: {response.decode()}")

        except ssl.SSLError as e:
            print(f"SSL error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.secure_socket.close()


if __name__ == "__main__":
    client = VPNClient()
    client.connect_to_vpn()



        
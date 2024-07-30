import socket
import toml
import ssl
import threading
import logging
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# Setup logging
logging.basicConfig(level=logging.INFO)

@dataclass
class VPNData:
    server_address: str
    server_hostname: str
    port: int
    local_port: int

class Configuration:
    def __init__(self, target_file: str) -> None:
        self.file = target_file

    def load_config_data(self) -> VPNData:
        with open(self.file, 'r') as config_file:
            config_data = toml.load(config_file)

        return VPNData(
            server_address=config_data['server']['server_address'],
            server_hostname=config_data['server']['server_hostname'],
            port=config_data['server']['port'],
            local_port=config_data['server']['local_port']
        )

class VPNClient:
    client_config: Configuration

    def __init__(self, config_file: str):
        self.client_config = Configuration(config_file)
        self.configuration: VPNData = self.client_config.load_config_data()
        self.server_address = self.configuration.server_address
        self.port = self.configuration.port
        self.server_hostname = self.configuration.server_hostname
        self.local_port = self.configuration.local_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.create_default_context()

        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        self.secure_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.server_hostname)
        self.symmetric_key = Fernet.generate_key()
        self.cipher = Fernet(self.symmetric_key)

    def connect_to_vpn(self):
        try:
            self.secure_socket.connect((self.server_address, self.port))
            logging.info(f"Connected to VPN server at {self.server_address}:{self.port}")

            server_public_key_pem = self.secure_socket.recv(4096)
            server_public_key = serialization.load_pem_public_key(server_public_key_pem)

            encrypted_symmetric_key = server_public_key.encrypt(
                self.symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.secure_socket.sendall(encrypted_symmetric_key)

            self.start_local_proxy()

        except ssl.SSLError as e:
            logging.error(f"SSL error: {e}")
            raise
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            raise
       

        finally:
            self.secure_socket.close()

    def start_local_proxy(self):
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_socket.bind(('127.0.0.1', self.local_port))
        local_socket.listen(5)
        logging.info(f"Local proxy started on port {self.local_port}")

        while True:
            client_conn, client_addr = local_socket.accept()
            threading.Thread(target=self.handle_local_connection, args=(client_conn,)).start()

    def handle_local_connection(self, client_conn):
        try:
            while True:
                data = client_conn.recv(4096)
                if not data:
                    break
                logging.info(f"Data sent to VPN server: {len(data)} bytes")
                encrypted_data = self.cipher.encrypt(data)
                self.secure_socket.sendall(encrypted_data)

                response_chunks = []
                while True:
                    encrypted_response = self.secure_socket.recv(4096)
                    if not encrypted_response:
                        break
                    response_chunks.append(encrypted_response)
                    if len(encrypted_response) < 4096:
                        break

                encrypted_response = b''.join(response_chunks)
                response = self.cipher.decrypt(encrypted_response)
                client_conn.sendall(response)
                logging.info(f"Data received from VPN server: {len(response)} bytes")

        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            client_conn.close()



if __name__ == "__main__":
    client = VPNClient('config.toml')
    client.connect_to_vpn()


        
import ssl
import toml
import socket
import logging
import threading
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
    """
    Initializes a Configuration object with a target file.

    Args:
        target_file (str): The path to the configuration file.

    Returns:
        None
    """
    def __init__(self, target_file: str) -> None:
        self.file: str = target_file

    def load_config_data(self) -> VPNData:
        """
        Loads configuration data from a file and returns it as a VPNData object.

        Returns:
            VPNData: An object containing the server address, server hostname, port, and local port.
        """
        with open(self.file, 'r') as config_file:
            config_data = toml.load(config_file)

        return VPNData(
            server_address=config_data['server']['server_address'],
            server_hostname=config_data['server']['server_hostname'],
            port=config_data['server']['port'],
            local_port=config_data['server']['local_port']
        )

class VPNClient:
    def __init__(self, config_file: str):
        """
        Initializes a VPNClient object with a target configuration file.

        Args:
            config_file (str): The path to the configuration file.

        Returns:
            None
        """
        self.client_config = Configuration(config_file)
        self.configuration: VPNData = self.client_config.load_config_data()
        self.server_address = self.configuration.server_address
        self.port = self.configuration.port
        self.server_hostname = self.configuration.server_hostname
        self.local_port = self.configuration.local_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.create_default_context()
        self.local_socket = None  # Initialize to None, will be used in start_local_proxy

        # Disable hostname and certificate verification for self-signed certificates
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        self.secure_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.server_hostname)
        self.symmetric_key = Fernet.generate_key()
        self.cipher = Fernet(self.symmetric_key)
        self.is_running = False  # To track the state of the VPN

    def connect_to_vpn(self):
        """
        Establishes a secure connection to the VPN server.

        Connects to the VPN server at the specified address and port, receives the server's public key,
        encrypts the symmetric key with the server's public key, and sends it to the server.
        Then, starts a local proxy to forward traffic through the VPN.

        Args:
            None

        Returns:
            None
        """
        try:
            self.secure_socket.connect((self.server_address, self.port))
            logging.info(f"Connected to VPN server at {self.server_address}:{self.port}")

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

            # Start local proxy to forward traffic through the VPN
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
        """
        Starts a local proxy to forward traffic through the VPN.

        Args:
            None

        Returns:
            None
        """
        self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_socket.bind(('127.0.0.1', self.local_port))
        self.local_socket.listen(5)
        logging.info(f"Local proxy started on port {self.local_port}")
        self.is_running = True

        while self.is_running:
            client_conn, client_addr = self.local_socket.accept()
            threading.Thread(target=self.handle_local_connection, args=(client_conn,)).start()

    def handle_local_connection(self, client_conn):
        """
        Handles incoming connections from the local proxy.

        This function is responsible for receiving data from the local connection
        encrypting it, and sending it to the VPN server. It also receives the
        response from the VPN server, decrypts it, and sends it back to the local
        connection.

        Args:
            client_conn (socket): The local connection to handle.

        Returns:
            None
        """
        try:
            while self.is_running:
                data = client_conn.recv(4096)
                if not data:
                    break
                logging.info(f"Received data from local connection: {len(data)} bytes")
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

        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            client_conn.close()

    def disconnect_from_vpn(self):
        """
        Disconnects from the VPN and stops the local proxy.

        This method sets the `is_running` flag to False, closes the local socket if it exists,
        and closes the secure socket if it exists. It also logs a message to indicate that
        the VPN connection has been disconnected and the local proxy has been stopped.

        Args:
            None

        Returns:
            None
        """
        self.is_running = False
        if self.local_socket:
            self.local_socket.close()
        if self.secure_socket:
            self.secure_socket.close()
        logging.info("Disconnected from VPN and stopped local proxy")



if __name__ == "__main__":
    client = VPNClient('config.toml')
    client.connect_to_vpn()
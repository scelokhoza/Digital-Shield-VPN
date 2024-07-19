import ssl
import socket
import threading
import select
import time
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet


class VPNServer:
    def __init__(self, server_address='0.0.0.0', port=8080, certfile='server.crt', keyfile='server.key'):
        """
        Initializes the VPNServer with the given server address, port, certificate, and key files.
        Generates RSA keys for secure communication.
        
        Parameters:
        server_address (str): IP address to bind the server to.
        port (int): Port to listen on.
        certfile (str): Path to the SSL certificate file.
        keyfile (str): Path to the SSL key file.
        """
        self.server_address = server_address
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.certfile = certfile
        self.keyfile = keyfile
        self.clients = {}  # Dictionary to store client addresses and their threads
        self.client_traffic = {}  # Dictionary to store client IPs and their data usage

        # Generate RSA keys for the server
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        # Serialize public key to send to the client
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


    def start_vpn(self):
        """
        Starts the VPN server, binding to the specified address and port.
        Listens for incoming connections and spawns a new thread to handle each client.
        Also starts a thread to handle admin commands.
        """
        try:
            self.server_socket.bind((self.server_address, self.port))
            self.server_socket.listen(5)
            print(f"Server started on {self.server_address}:{self.port}")

            threading.Thread(target=self.admin_commands).start()

            while True:
                client_socket, client_address = self.server_socket.accept()
                self.clients[client_address] = client_socket
                self.client_traffic[client_address[0]] = 0
                print(f"Connection from {client_address}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                client_thread.start()

        except PermissionError as e:
            print(f"Permission denied: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.server_socket.close()


    def handle_client(self, client_socket, client_address):
        """
        Handles communication with a connected client.
        Performs SSL handshake, exchanges encryption keys, and forwards data to the destination server.
        
        Parameters:
        client_socket (socket.socket): The socket connected to the client.
        client_address (tuple): The client's address.
        """
        try:
            # Set socket timeout to handle idle connections
            client_socket.settimeout(60)
            
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
                try:
                    encrypted_data = ssl_client_socket.recv(4096)
                    if not encrypted_data:
                        break

                    data = cipher.decrypt(encrypted_data)
                    self.client_traffic[client_address[0]] += len(data)
                    response = self.forward_to_destination(data)
                    encrypted_response = cipher.encrypt(response)
                    ssl_client_socket.sendall(encrypted_response)
                except socket.timeout:
                    print("Socket timed out. Closing connection.")
                    break
                except ssl.SSLError as e:
                    print(f"SSL error: {e}")
                    break
                except Exception as e:
                    print(f"An error occurred while handling client data: {e}")
                    break

        except ssl.SSLError as e:
            print(f"SSL error during initial handshake: {e}")
        except socket.timeout:
            print("Initial socket connection timed out. Closing connection.")
        except Exception as e:
            print(f"An error occurred during client handling: {e}")
        finally:
            ssl_client_socket.close()
            client_socket.close()
            del self.clients[client_address]


    def forward_to_destination(self, data):
        """
        Forwards client data to the intended destination server and returns the response.
        
        Parameters:
        data (bytes): The data received from the client to be forwarded.
        
        Returns:
        bytes: The response data from the destination server.
        """
        try:
            headers = data.split(b'\r\n')
            host_header = next((h for h in headers if b'Host:' in h), None)
            if not host_header:
                raise ValueError("No Host header found")
            
            host = host_header.split(b' ')[1].decode('utf-8')
            
            url = urlparse(f'http://{host}')
            
            port = url.port or 80
            if port == 443:
                url = urlparse(f'https://{host}')
            
            destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            destination_socket.settimeout(30)

            if url.scheme == 'https':
                context = ssl.create_default_context()
                destination_socket = context.wrap_socket(destination_socket, server_hostname=url.hostname)
            
            destination_socket.connect((url.hostname, port))
            destination_socket.sendall(data)
            
            response_data = b""
            while True:
                chunk = destination_socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            
            destination_socket.close()
            return response_data
        
        except Exception as e:
            print(f"Error forwarding data to destination: {e}")
            return b""


    def admin_commands(self):
        """
        Handles admin commands to manage and troubleshoot the VPN server.
        """
        while True:
            command = input("Enter command: ").strip().lower()
            if command == "list clients":
                self.list_clients()
            elif command.startswith("show traffic"):
                _, client_ip = command.split()
                self.show_traffic(client_ip)
            elif command.startswith("disconnect"):
                _, client_ip = command.split()
                self.disconnect_client(client_ip)
            elif command == "quit":
                self.quit_server()
                break
            else:
                print("Unknown command")


    def list_clients(self):
        """
        Lists all connected clients.
        """
        if self.clients:
            print("Connected clients:")
            for client_address in self.clients.keys():
                print(client_address)
        else:
            print("No connected clients.")


    def show_traffic(self, client_ip):
        """
        Shows the traffic data for a specific client.
        
        Parameters:
        client_ip (str): The IP address of the client.
        """
        traffic = self.client_traffic.get(client_ip, None)
        if traffic is not None:
            print(f"Traffic for {client_ip}: {traffic} bytes")
        else:
            print(f"No traffic data for {client_ip}")


    def disconnect_client(self, client_ip):
        """
        Disconnects a specific client.
        
        Parameters:
        client_ip (str): The IP address of the client.
        """
        for client_address, client_socket in list(self.clients.items()):
            if client_address[0] == client_ip:
                client_socket.close()
                del self.clients[client_address]
                print(f"Disconnected client {client_ip}")
                return
        print(f"No client found with IP {client_ip}")


    def quit_server(self):
        """
        Shuts down the server and disconnects all clients.
        """
        print("Shutting down server...")
        for client_socket in self.clients.values():
            client_socket.close()
        self.server_socket.close()
        print("Server shut down.")



if __name__ == '__main__':
    server = VPNServer()
    server.start_vpn()



import socket
import ssl

class VPNClient:
    def __init__(self, server_address='0.0.0.0', port=8080, server_hostname='scelo'):
        self.server_address = server_address
        self.port = port
        self.server_hostname = server_hostname
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.create_default_context()
        self.secure_socket = self.context.wrap_socket(self.client_socket, server_hostname=self.server_hostname)


    def connect_to_vpn(self):
        try:
            self.secure_socket.connect((self.server_address, self.port))
            print(f"Connected to VPN server at {self.server_address}:{self.port}")
            self.secure_socket.sendall(b'Hello from client')
            response = self.secure_socket.recv(4096)
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

        
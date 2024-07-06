import socket
import ssl
import threading



class VPNServer:
    def __init__(self, server_address='0.0.0.0', port=8080):  
        self.server_address = server_address
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def start_vpn(self):
        try:
            self.server_socket.bind((self.server_address, self.port))
            self.server_socket.listen(5)
            print(f"Server started on {self.server_address}:{self.port}")
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connection from {client_address}")
                # Handle the client connection
                client_socket.close()
        except PermissionError as e:
            print(f"Permission denied: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.server_socket.close()
            


if __name__ == '__main__':
    server = VPNServer()
    server.start_vpn()
    
    
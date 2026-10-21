import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 6768

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_socket.bind((SERVER_IP, SERVER_PORT))

print(f"UDP server listening on {SERVER_IP}:{SERVER_PORT}")

data, client_address = server_socket.recvfrom(1024)

print("Received data:", data.decode())
print("From:", client_address)
data, client_address = server_socket.recvfrom(1024)
print("Received data:", data.decode())
print("From:", client_address)

server_socket.close()
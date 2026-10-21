import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 6767

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client_socket.connect((SERVER_IP, SERVER_PORT))

client_socket.sendall(b"FIRST\n")
client_socket.sendall(b"SECOND\n")

print("Data sent to server.")

client_socket.shutdown(socket.SHUT_WR)

response = client_socket.recv(1024)

print("Received data:", response.decode())

client_socket.close()

print("Client socket closed.")
import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 6767

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.bind((SERVER_IP, SERVER_PORT))
server_socket.listen(2)

print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

client_socket, client_address = server_socket.accept()

print("Client connected:", client_address)

buffer = b""

while True:
    data = client_socket.recv(1024)

    if not data:
        break

    buffer += data

    while b"\n" in buffer:
        message, buffer = buffer.split(b"\n", 1)
        print("Received message:", message.decode())

client_socket.sendall(b"Hello, Client!")

client_socket.close()
server_socket.close()
import socket
SERVER_IP = "127.0.0.1"
SERVER_PORT = 6768
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.sendto(b"Hello, UDP Server!", (SERVER_IP, SERVER_PORT))
client_socket.sendto(b"Another message to the UDP Server!", (SERVER_IP, SERVER_PORT))
client_socket.close()

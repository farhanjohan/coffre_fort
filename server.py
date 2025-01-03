import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 5000))  # Bind to port 5000
server.listen(1)
print("Server: Waiting for connection...")

conn, addr = server.accept()
print(f"Server: Connected to {addr}")


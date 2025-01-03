import socket

def connect(ipadd):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ipadd, 7000))  # Bind to port 
    server.listen(1)
    print("Server: Waiting for connection...")

    conn, addr = server.accept()
    print(f"Server: Connected to {addr}")

    conn.close()
    server.close()


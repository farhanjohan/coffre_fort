import socket

def client_connect(ipadd,port):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ipadd,port))  # Connect to server at localhost:5000
    print("Connected to the server.")


def server_connect(ipadd,port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ipadd,port))  # Bind to port 
    server.listen(1)
    print("Server: Waiting for connection...")

    conn, addr = server.accept()
    print(f"Server: Connected to {addr}")

    conn.close()
    server.close()



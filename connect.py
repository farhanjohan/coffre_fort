import socket
from auth import *

def client_connect(ipadd,port):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ipadd, 6000))  # Connect to server at localhost:6000
    print("Connected to the server.")

    username = input("Enter username: ")
    password = input("Enter password: ")
    client.send(f"{username}::{password}".encode())

    response = client.recv(1024).decode()
    if response == "AUTH_SUCCESS":
        print("Authentication successful.")


def server_connect(ipadd,port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ipadd,6000))  # Bind to port 
    server.listen(1)
    print("Server: Waiting for connection...")

    conn, addr = server.accept()
    print(f"Server: Connected to {addr}")

    #receive password and username
    data = conn.recv(1024).decode()
    username, password = data.split("::")

    # Authenticate the user
    vault_path = authenticate_user(username, password)
    if vault_path:
        conn.send("AUTH_SUCCESS".encode())
        print(f"User {username} authenticated.")

    conn.close()
    server.close()



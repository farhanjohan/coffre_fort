import socket

def client_connect(ipadd):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ipadd, 5000))  # Connect to server at localhost:5000
    print("Connected to the server.")
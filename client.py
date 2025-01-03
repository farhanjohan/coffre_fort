import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("", 5000))  # Connect to server at localhost:5000
import random
import connect
import socket

def generate_private_key(prime):
    """Génère une clé privée aléatoire."""
    return random.randint(2, prime - 2)

def compute_public_key(prime, base, private_key):
    """Calcule la clé publique."""
    return pow(base, private_key, prime)

def compute_shared_secret(prime, public_key, private_key):
    """Calcule le secret partagé."""
    return pow(public_key, private_key, prime)

def echange_cles_client():

    # Step 1: Receive server's public key and parameters
    data = client.recv(1024).decode()
    prime, base, server_public_key = map(int, data.split(","))
    print(f"Client: Received parameters -> prime: {prime}, base: {base}, server public key: {server_public_key}")

    # Step 2: Generate private and public keys
    client_private_key = generate_private_key(prime)
    client_public_key = compute_public_key(prime, base, client_private_key)
    print(f"Client: Sending public key: {client_public_key}")

    # Step 3: Send public key to server
    client.send(str(client_public_key).encode())

    # Step 4: Compute shared secret
    shared_secret = compute_shared_secret(prime, server_public_key, client_private_key)
    print(f"Client: Shared secret is {shared_secret}")


def echange_cles_server():

    ######### ON PEUT CHANGER LES P ET B ###########

    prime = 23  # Public prime number
    base = 5    # Public base

    server_private_key = generate_private_key(prime)
    server_public_key = compute_public_key(prime, base, server_private_key)

    # Step 1: Create, bind, and listen on the server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("25.15.154.124", 12345))  # Bind to all interfaces on port 12345
    server.listen(1)  # Listen for incoming connections
    print("Server is listening on port 12345...")

    conn, addr = server.accept()  # Accept a connection
    print(f"Connected to {addr}")

    # Step 2: Send public key to client
    conn.send(f"{prime},{base},{server_public_key}".encode())

    # Step 2: Receive client's public key
    client_public_key = int(conn.recv(1024).decode())
    print(f"Server: Received client's public key: {client_public_key}")

    # Step 3: Compute shared secret
    shared_secret = compute_shared_secret(prime, client_public_key, server_private_key)
    print(f"Server: Shared secret is {shared_secret}")







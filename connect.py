import random
import connect
import socket
from auth import *

def generate_private_key(prime):
    """Génère une clé privée aléatoire."""
    return random.randint(2, prime - 2)

def compute_public_key(prime, base, private_key):
    """Calcule la clé publique."""
    return pow(base, private_key, prime)

def compute_shared_secret(prime, public_key, private_key):
    """Calcule le secret partagé."""
    return pow(public_key, private_key, prime)

def client_connect(ipadd,port):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ipadd, 6000))  # Connect to server at localhost:6000
    print("Connected to the server.")

    username = input("Enter username: ")
    password = input("Enter password: ")
    client.send(f"{username}::{password}".encode())

    # Derive the private key from the password
    derived_key = sponge_hash(password)
    zkp = ZKPAuth(derived_key, p=23, g=5)

    # Generate the public key and commitment (M)
    M = zkp.generer_preuve()
    data = f"{zkp.cle_publique},{M}"
    client.sendall(data.encode())
    print(f"Client: Sent public key and commitment: {data}")

    # Receive challenge from the server
    challenge = int(client.recv(1024).decode())
    print(f"Client: Received challenge: {challenge}")

    # Generate proof (preuve) and send it to the server
    preuve = zkp.repondre_challenge(challenge)
    client.sendall(str(preuve).encode())
    print(f"Client: Sent proof: {preuve}")

    # Receive authentication result
    response = client.recv(1024).decode()
    if response == "AUTH_SUCCESS":
        print("Client: Authentication successful!")
    else:
        print("Client: Authentication failed.")
        
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
    


def server_connect(ipadd,port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ipadd,6000))  # Bind to port 
    server.listen(1)
    print("Server: Waiting for connection...")

    conn, addr = server.accept()
    print(f"Server: Connected to {addr}")

    try:
        # Receive username and password
        data = conn.recv(1024).decode()
        username, password = data.split("::")
        print(f"Server: Received credentials for {username}.")

        # Derive the private key from the password
        derived_key = sponge_hash(password)
        zkp = ZKPAuth(derived_key, p=23, g=5)

        # Receive the public key and commitment (M) from the client
        data = conn.recv(1024).decode()
        cle_publique, M = map(int, data.split(","))
        print(f"Server: Received public key and Commitment: {M}")

        # Generate and send a challenge to the client
        challenge = secrets.randbelow(zkp.p - 1)
        conn.sendall(str(challenge).encode())
        print(f"Server: Sent challenge: {challenge}")

        # Receive proof (preuve) from the client
        preuve = int(conn.recv(1024).decode())
        print(f"Server: Received proof: {preuve}")

        # Verify proof
        zkp.cle_publique = cle_publique
        zkp.M = M
        verification = zkp.verifier_preuve(challenge, preuve)

        if verification:
            conn.send("AUTH_SUCCESS".encode())
            print(f"Server: User {username} authenticated.")
        else:
            conn.send("AUTH_FAIL".encode())
            print(f"Server: Authentication failed for {username}.")

            ######### ON PEUT CHANGER LES P ET B ###########

        prime = 23  # Public prime number
        base = 5    # Public base

        server_private_key = generate_private_key(prime)
        server_public_key = compute_public_key(prime, base, server_private_key)

        # Step 1: Send public key to client
        conn.send(f"{prime},{base},{server_public_key}".encode())

        # Step 2: Receive client's public key
        client_public_key = int(conn.recv(1024).decode())
        print(f"Server: Received client's public key: {client_public_key}")

        # Step 3: Compute shared secret
        shared_secret = compute_shared_secret(prime, client_public_key, server_private_key)
        print(f"Server: Shared secret is {shared_secret}")

    finally:
        return
        #server.close()



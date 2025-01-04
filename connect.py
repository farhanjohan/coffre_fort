import random
import connect
import socket
from auth import *
import encryption
import credentials

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

    response= client.recv(1024).decode()
    while response == "username deja existe":
        print("username deja existe")
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
    
    # Prompt the client for action
    print("\nWhat do you want to do?")
    print("1. Upload a file")
    print("2. Open a file")
    choice = input("Enter your choice (1 or 2): ")

    client.send(choice.encode())  # Send choice to server

    print("Choice sent to server. Awaiting response...")
    if choice == "2":
        # Receive and display the list of files
        file_list = client.recv(1024).decode()
        print("Files in your repository:")
        print(file_list)
        selected_file = input("Enter the name of the file you want to open: ")
        client.send(selected_file.encode())

        # Receive the file content
        file_content = client.recv(1024).decode()
        print(f"Content of {selected_file}:")
        print(file_content)


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

        user_credentials = credentials.load_user_credentials()

        if username not in user_credentials:
            os.makedirs(username, exist_ok=True)

            # Génération des clés
            p = encryption.generate_large_prime()
            q = encryption.generate_large_prime()
            n = p * q
            phi = (p - 1) * (q - 1)

            # Clé publique (e, n)
            e = 65537
            while encryption.gcd(e, phi) != 1:
                e += 2

            # Clé privée (d, n)
            d = encryption.mod_inverse(e, phi)

            # Save keys locally
            with open(f"{username}/public_key.txt", "w") as pub:
                pub.write(f"{e},{n}")
            with open(f"{username}/private_key.txt", "w") as priv:
                priv.write(f"{d},{n}")
            print("Clés générées avec succès !")

            # Add to the in-memory dictionary
            user_credentials[username] = {
                "password": password,
                "public_key": (e, n),
                "private_key": (d, n),
            }

            # Save to JSON file
            credentials.save_user_credentials(user_credentials)
            print(f"Informations utilisateur enregistrées avec succès pour {username}.")

        
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

        choice = conn.recv(1024).decode()
        if choice == "1":
            print("Server: Client chose to upload a file.")
            #####
        elif choice == "2":
            print("Server: Client chose to open a file.")
            user_dir = username  # Assuming user's directory is named after the username

            if os.path.exists(user_dir):
                files = os.listdir(user_dir)
                if files:
                    file_list = "\n".join(files)
                else:
                    file_list = "No files available."
            else:
                file_list = "User repository not found."

            conn.send(file_list.encode())  # Send the list of files to the client

            # Receive selected file from the client
            selected_file = conn.recv(1024).decode()
            file_path = os.path.join(user_dir, selected_file)

            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    file_content = f.read()
            else:
                file_content = "File not found."

            conn.send(file_content.encode())  # Send the content of the file
       
    finally:
        return
        #server.close()



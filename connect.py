import random
import socket
from auth import *
from simplecobrafile import *
import encryption
import credentials
import pickle

def clean_file_of_nulls(file_path):
    with open(file_path, "rb") as infile:
        content = infile.read()
    
    # Remove all NULL characters
    cleaned_content = content.replace(b'\x00', b'')
    
    # Rewrite the file with cleaned content
    with open(file_path, "wb") as outfile:
        outfile.write(cleaned_content)

def derive_256_bit_key(shared_secret):
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder="big")
    while len(shared_secret_bytes) < 32:  # Ensure at least 32 bytes (256 bits)
        shared_secret_bytes += shared_secret_bytes  # Repeat bytes if too short
    return shared_secret_bytes[:32]  # Trim to 256 bits (32 bytes)

def decrypt_and_store_file(encrypted_file_path, private_key, output_path):
    d, n = private_key
    chunk_size = (n.bit_length() + 7) // 8  # RSA block size for decryption
    decrypted_data = []

    with open(encrypted_file_path, "rb") as infile:
        while chunk := infile.read(chunk_size):  # Read encrypted chunks
            encrypted_int = int.from_bytes(chunk, byteorder="big")  # Convert chunk to integer
            decrypted_int = pow(encrypted_int, d, n)  # Decrypt: m = c^d mod n
            
            # Calculate maximum chunk size based on encryption padding
            max_chunk_size = n.bit_length() // 8 - 1  # RSA block size minus 1 for padding
            
            # Convert decrypted integer to bytes and strip padding
            decrypted_chunk = decrypted_int.to_bytes(max_chunk_size, byteorder="big").rstrip(b"\x00")
            decrypted_data.append(decrypted_chunk)  # Append to data list

    # Combine all chunks and write to output
    with open(output_path, "wb") as outfile:
        outfile.write(b"".join(decrypted_data))  # Combine decrypted chunks
    print(f"Decrypted file saved at {output_path}.")
    clean_file_of_nulls(output_path)

def encrypt_and_store_file(file_path, public_key, output_path):
    e, n = public_key
    max_chunk_size = n.bit_length() // 8 - 1  # Maximum plaintext size per RSA block
    with open(file_path, "rb") as infile, open(output_path, "wb") as outfile:
        while chunk := infile.read(max_chunk_size):  # Read plaintext chunks
            chunk_int = int.from_bytes(chunk, byteorder="big")  # Convert to integer
            encrypted_int = pow(chunk_int, e, n)  # Encrypt: c = m^e mod n
            encrypted_chunk = encrypted_int.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
            outfile.write(encrypted_chunk)

    print(f"File encrypted and stored at {output_path}.")

def generate_private_key(prime):
    """Génère une clé privée aléatoire."""
    return random.randint(2, prime - 2)

def compute_public_key(prime, base, private_key):
    """Calcule la clé publique."""
    return pow(base, private_key, prime)

def compute_shared_secret(prime, public_key, private_key):
    """Calcule le secret partagé."""
    return pow(public_key, private_key, prime)

def client_connect(ipadd):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ipadd, 6000))  # Connect to server at :6000
    print("Connected to the server.")

    username = input("Enter username: ")
    password = input("Enter password: ")
    client.send(f"{username}::{password}".encode())

    response = client.recv(1024).decode()
    if response == "NEW_USER":
        print("New user detected. Initiating creation...")

        # Create a directory for the user locally
        os.makedirs(username, exist_ok=True)

        # Generate RSA keys
        p = encryption.generate_large_prime()
        q = encryption.generate_large_prime()
        n = p * q
        phi = (p - 1) * (q - 1)

        # Public key (e, n)
        e = 65537
        while encryption.gcd(e, phi) != 1:
            e += 2

        # Private key (d, n)
        d = encryption.mod_inverse(e, phi)

        # Save keys locally
        public_key_path = os.path.join(username, "public_key.txt")
        private_key_path = os.path.join(username, "private_key.txt")

        with open(public_key_path, "w") as pub:
            pub.write(f"{e},{n}")
        with open(private_key_path, "w") as priv:
            priv.write(f"{d},{n}")

        print("Keys generated successfully!")

        # Send public key to the server
        with open(public_key_path, "r") as pub:
            public_key_data = pub.read()
        client.send(public_key_data.encode())
        print("Public key sent to the server.")

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
    key_256 = derive_256_bit_key(shared_secret)

    while True :
        # Prompt the client for action
        print("\nWhat do you want to do?")
        print("1. Upload a file")
        print("2. Open a file")
        choice = input("Enter your choice (1 or 2): ")

        shared_secret=str(shared_secret)
        crypted_message = encryption.send_message_enc(choice,shared_secret)
        client.send(pickle.dumps(crypted_message))  # Send choice to server
        print("Choice sent to server. Awaiting response...")
        if choice == "1":
            # Prompt the client to specify the file to upload
            file_to_upload = input("Enter the path of the file to upload: ")

            # Ensure the file exists
            if not os.path.exists(file_to_upload):
                print("Error: File does not exist.")
                client.send(b"FILE_NOT_FOUND")
            else:

                # Send the file name
                file_name = os.path.basename(file_to_upload)
                client.send(file_name.encode())
                
                # Send the file content
                with open(file_to_upload, "rb") as file:
                    file_content = file.read()
                client.sendall(file_content)

                print(f"File '{file_name}' has been uploaded successfully.")

        elif choice == "2":
            # Receive and display the list of files
            file_list = client.recv(1024).decode()
            print("Files in your repository:")
            print(file_list)
            selected_file = input("Enter the name of the file you want to open: ")
            client.send(selected_file.encode())

            # Receive the encrypted file content
            encrypted_content = client.recv(1024 * 10)  # Adjust size as needed
            if encrypted_content == b"File not found.":
                print("The requested file was not found on the server.")
            else:
                print(f"Encrypted content for '{selected_file}' received.")

                # COBRA decrypt the file
                selected_file = os.path.splitext(selected_file)[0]
                cobra = SimpleCOBRA(key_256)  # Ensure this matches the server key
                cobra_decrypted_content = bytearray()
                chunk_size = 16
                for i in range(0, len(encrypted_content), chunk_size):
                    chunk = encrypted_content[i:i + chunk_size]
                    cobra_decrypted_content.extend(cobra.decrypt_block(chunk))

                # Save intermediate COBRA-decrypted content for debugging 
                intermediate_file = f"intermediate_{selected_file}.dec"
                with open(intermediate_file, "wb") as f:
                    f.write(cobra_decrypted_content)

                # RSA decrypt the COBRA-decrypted content
                user_dir = username
                private_key_path = os.path.join(user_dir, "private_key.txt")
                with open(private_key_path, "r") as priv_key_file:
                    private_key = tuple(map(int, priv_key_file.read().split(",")))

                decrypted_file_path = os.path.join(user_dir, selected_file)
                decrypt_and_store_file(intermediate_file, private_key, decrypted_file_path)

                # remove intermediate file
                os.remove(intermediate_file)
                print(f"File decrypted and saved as {decrypted_file_path}.")
        continue_choice = input("Do you want to continue? (yes/no): ").strip().lower()
        client.send(continue_choice.encode())
        if continue_choice != "yes":
            print("Exiting session.")
            break

def server_connect(ipadd):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ipadd,6000))  # Bind to port 
    server.listen(1)
    print("Server: Waiting for connection...")

    conn, addr = server.accept()
    print(f"Server: Connected to {addr}")

    try :
        # Receive username and password
        data = conn.recv(1024).decode()
        username, password = data.split("::")
        print(f"Server: Received credentials for {username}.")

        user_credentials = credentials.load_user_credentials()
        
        if username not in user_credentials:
            print(f"Server: User '{username}' does not exist. Creating a new one...")
            conn.send("NEW_USER".encode())

            # Receive the public key from the client
            public_key_data = conn.recv(2048).decode()  # Adjust buffer size if needed
            e, n = map(int, public_key_data.split(","))  # Parse the public key components
            print(f"Server: Received public key for '{username}': e={e}, n={n}")

            # Create a directory for the user 
            os.makedirs(username, exist_ok=True)

            # Save the public key in a text file in the user's directory
            public_key_path = os.path.join(username, "public_key.txt")
            with open(public_key_path, "w") as pub_file:
                pub_file.write(public_key_data)
            print(f"Server: Public key saved at: {public_key_path}")

            # Update in-memory user credentials
            user_credentials[username] = {
                "password": password,
                "public_key": (e, n),
            }

            # Save updated credentials to the JSON file
            credentials.save_user_credentials(user_credentials)
            print(f"Server: User credentials updated and saved for '{username}'.")

        else:
            conn.send("OLD_USER".encode())

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
        key_256 = derive_256_bit_key(shared_secret)

        while True:
            ###### ENCRYPTED MESSAGE HASHMAC ET chiffrés avec une clé de session et chaque échange est authentifié avec un hashmac ######
            shared_secret=str(shared_secret)
            choice = conn.recv(1024)
            ciphertext, hmac = pickle.loads(choice)
            choice = (encryption.receive_message_dec(ciphertext,hmac,shared_secret)).decode()
            
            if choice == "1":
                print("Server: Client chose to upload a file.")

                # Receive the file name
                file_name = conn.recv(1024).decode()
                print(f"Server: Receiving file '{file_name}'.")

                # Receive the file content
                file_content = b""
                while chunk := conn.recv(1024):
                    file_content += chunk
                    if len(chunk) < 1024:  # Assume end of file if chunk size < 1024
                        break

                # Save the file temporarily in memory
                user_dir = username
                os.makedirs(user_dir, exist_ok=True)  # Ensure the user's directory exists
                temp_file_path = os.path.join(user_dir, file_name)
                with open(temp_file_path, "wb") as temp_file:
                    temp_file.write(file_content)
                print(f"Server: File '{file_name}' received.")

                # Encrypt the file using the user's public key
                public_key_path = os.path.join(user_dir, "public_key.txt")
                with open(public_key_path, "r") as pub_key_file:
                    public_key = pub_key_file.read()

                e, n = map(int, public_key.split(","))
                encrypted_file_path = os.path.join(user_dir, f"{file_name}.enc")
                encrypt_and_store_file(temp_file_path, (e, n), encrypted_file_path)

                # Remove the plaintext file
                os.remove(temp_file_path)
                print(f"Server: File '{file_name}' encrypted and stored as '{encrypted_file_path}'.")

            elif choice == "2":
                print("Server: User chose to open a file.")
                print("Server: Waiting for the user to choose a file.")
                user_dir = username 

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
                encrypted_file_path = os.path.join(user_dir, f"{selected_file}.cobra")
                cobra = SimpleCOBRA(key_256)  # a remplacer
                cobra.encrypt_file(file_path, encrypted_file_path)

                with open(encrypted_file_path, "rb") as f:
                    encrypted_content = f.read()

                conn.send(encrypted_content)  # Send encrypted file content
                print(f"Server: Encrypted file {encrypted_file_path} sent.")
                os.remove(encrypted_file_path)
            else:
                conn.send(b"File not found.")
            
            continue_choice = conn.recv(1024).decode()
            if continue_choice != "yes":
                print("Server: Client chose to exit.")
                break
    finally:
        return
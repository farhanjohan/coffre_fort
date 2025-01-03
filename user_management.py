import encryption
import os
import json
from credentials import *

# Load credentials at startup
user_credentials = load_user_credentials()

def create_account(username, password):
    if username in user_credentials:
        print(f"L'utilisateur '{username}' existe déjà.")
        return

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
    save_user_credentials(user_credentials)
    print(f"Informations utilisateur enregistrées avec succès pour {username}.")

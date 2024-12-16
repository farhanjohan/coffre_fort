import encryption
import os

def create_account():
    username = input("Entrez un nom d'utilisateur : ")
    os.makedirs(username, exist_ok=True)
    print(f"Répertoire créé pour l'utilisateur : {username}")

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

    # Sauvegarder les clés
    with open(f"{username}/public_key.txt", "w") as pub:
        pub.write(f"{e},{n}")
    with open(f"{username}/private_key.txt", "w") as priv:
        priv.write(f"{d},{n}")
    print("Clés générées avec succès !")
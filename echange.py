import random

def generate_private_key(prime):
    """Génère une clé privée aléatoire."""
    return random.randint(2, prime - 2)

def compute_public_key(prime, base, private_key):
    """Calcule la clé publique."""
    return pow(base, private_key, prime)

def compute_shared_secret(prime, public_key, private_key):
    """Calcule le secret partagé."""
    return pow(public_key, private_key, prime)









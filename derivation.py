def sponge_hash(password, iterations=100000):
    hash_value = sum(ord(char) for char in password) % 256
    for _ in range(iterations):
        hash_value = (hash_value * 31 + 7) % 256  # Exemple simple de hashage
    return hash_value

def derive_key(password):
    derived_key = sponge_hash(password)
    print(f"Clé dérivée : {derived_key}")
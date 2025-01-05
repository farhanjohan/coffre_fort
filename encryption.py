import random


##### ENCRYPTION RSA #######

def generate_large_prime():
    # Génération manuelle d'un nombre premier (simplifiée)
    while True:
        n = random.randint(10**5, 10**6)
        if is_prime(n):
            return n

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


############# hashmac ###########

def xor_encrypt_decrypt(data, key):
    """Encrypt or decrypt data using XOR with the key."""
    key = key * (len(data) // len(key)) + key[:len(data) % len(key)]
    return bytes(a ^ b for a, b in zip(data, key))

# Helper: Simple hash function
def simple_hash(data):
    """Simple hash function using bitwise operations."""
    hash_value = 0
    for byte in data:
        hash_value = ((hash_value << 5) - hash_value) + byte  # Simple hash like DJB2
        hash_value &= 0xFFFFFFFF  # Keep it 32-bit
    return hash_value.to_bytes(4, 'big')  # Return as 4 bytes

# Generate HMAC-like function
def generate_hmac(message, key):
    """Simple HMAC implementation using XOR and the simple hash function."""
    block_size = 64  # Block size for the hash input
    if len(key) > block_size:
        key = simple_hash(key)  # Reduce key size
    if len(key) < block_size:
        key = key.ljust(block_size, b'\x00')  # Pad key

    o_key_pad = bytes(b ^ 0x5C for b in key)
    i_key_pad = bytes(b ^ 0x36 for b in key)

    inner_hash = simple_hash(i_key_pad + message)
    return simple_hash(o_key_pad + inner_hash)

# Encrypt and Authenticate
def encrypt_and_authenticate(message, session_key):
    """Encrypt the message and generate its HMAC."""
    ciphertext = xor_encrypt_decrypt(message, session_key)
    hmac = generate_hmac(ciphertext, session_key)
    return ciphertext, hmac

# Verify and Decrypt
def verify_and_decrypt(ciphertext, hmac, session_key):
    """Verify the HMAC and decrypt the message."""
    calculated_hmac = generate_hmac(ciphertext, session_key)
    if hmac != calculated_hmac:
        raise ValueError("Message authentication failed!")
    return xor_encrypt_decrypt(ciphertext, session_key)

 ################## SEND Encrypted and Authenticate ###############
def send_message_enc(original_message,session_key):
    ciphertext, hmac = encrypt_and_authenticate(original_message, session_key)
    print("Ciphertext:", ciphertext)
    print("HMAC:", hmac.hex())
    return ciphertext,hmac


################## RECEIVE Verify and Decrypt ####################
def receive_message_dec(ciphertext,hmac,session_key): 
    try:
        decrypted_message = verify_and_decrypt(ciphertext, hmac, session_key)
        print("Decrypted Message:", decrypted_message.decode())
    except ValueError as e:
        print("Error:", e) 
    return decrypted_message
    
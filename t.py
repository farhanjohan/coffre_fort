def encrypt_and_store_file(file_path, public_key, output_path):
    e, n = public_key
    chunk_size = n.bit_length() // 8 - 1  # Maximum chunk size for RSA encryption
    with open(file_path, "rb") as infile, open(output_path, "wb") as outfile:
        while chunk := infile.read(chunk_size):  # Read chunks of valid size
            chunk_int = int.from_bytes(chunk, byteorder="big")
            encrypted_int = pow(chunk_int, e, n)  # Encrypt: c = m^e mod n
            encrypted_chunk = encrypted_int.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
            outfile.write(encrypted_chunk)

    print(f"File encrypted and stored at {output_path}.")



def decrypt_and_print_file(encrypted_file_path, private_key):
    d, n = private_key
    decrypted_data = b""
    chunk_size = (n.bit_length() + 7) // 8  # RSA block size for decryption
    with open(encrypted_file_path, "rb") as infile:
        while chunk := infile.read(chunk_size):  # Read encrypted chunks
            encrypted_int = int.from_bytes(chunk, byteorder="big")
            decrypted_int = pow(encrypted_int, d, n)  # Decrypt: m = c^d mod n
            decrypted_chunk = decrypted_int.to_bytes(chunk_size - 1, byteorder="big").rstrip(b"\x00")  # Remove padding
            decrypted_data += decrypted_chunk

    print("Decrypted Plaintext:")
    print(decrypted_data.decode("utf-8", errors="replace"))  # Decode to string


public_key = (65537, 87931952929)  # Replace with actual public key
file_path = "test.txt"  # Path to plaintext file
encrypted_file_path = "test.txt.enc"  # Path to save encrypted file

encrypt_and_store_file(file_path, public_key, encrypted_file_path)

private_key = (77254000193, 87931952929)  # Replace with actual private key
encrypted_file_path = "test.txt.enc"  # Path to encrypted file

decrypt_and_print_file(encrypted_file_path, private_key)





class CoffreFort:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def store_file(self, input_file, encrypted_file):
        cobra_key = os.urandom(16)
        cobra = SimpleCOBRA(cobra_key)

        cobra.encrypt_file(input_file, encrypted_file)

        encrypted_cobra_key = rsa_encrypt(self.public_key, cobra_key)
        return encrypted_cobra_key

    def retrieve_file(self, encrypted_file, decrypted_file, encrypted_cobra_key):
        cobra_key = rsa_decrypt(self.private_key, encrypted_cobra_key)
        cobra = SimpleCOBRA(cobra_key)

        cobra.decrypt_file(encrypted_file, decrypted_file)
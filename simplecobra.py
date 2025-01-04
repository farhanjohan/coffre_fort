import random

class SimpleCOBRA:
    def __init__(self, key):
        if not isinstance(key, (bytes, bytearray)):
            raise ValueError("Key must be a bytes object.")
        self.key = self.expand_key(key)
        self.s_boxes, self.reverse_s_boxes = self.generate_s_boxes()

    def expand_key(self, key):
        """Expands the key to create round keys."""
        if len(key) < 16:
            key += b"\x00" * (16 - len(key))
        expanded_key = []
        for i in range(33):
            expanded_key.append(self.custom_hash(key + bytes([i])))
        return expanded_key

    def custom_hash(self, data, rounds=1000):
        """A simplified custom hash function for key expansion."""
        hash_value = sum(data) % 256
        for _ in range(rounds):
            hash_value = (hash_value * 31 + 7) % 256
        return bytes((hash_value + i) % 256 for i in range(16))

    def generate_s_boxes(self):
        """Generate substitution boxes (S-boxes)."""
        s_boxes = []
        reverse_s_boxes = []
        random.seed(42)

        for _ in range(4):
            s_box = list(range(16))
            random.shuffle(s_box)
            reverse_s_box = {v: k for k, v in enumerate(s_box)}
            s_boxes.append(s_box)
            reverse_s_boxes.append(reverse_s_box)

        return s_boxes, reverse_s_boxes

    def substitute(self, block, round_num, reverse=False):
        """Applies substitution using the S-box."""
        s_box = self.reverse_s_boxes[round_num % 4] if reverse else self.s_boxes[round_num % 4]
        substituted = bytearray(block)
        for i in range(len(substituted)):
            lower_nibble = substituted[i] & 0x0F
            upper_nibble = (substituted[i] >> 4) & 0x0F
            substituted[i] = (s_box[lower_nibble] | (s_box[upper_nibble] << 4))
        return bytes(substituted)

    def add_round_key(self, block, key):
        """XOR the block with the round key."""
        return bytes(b ^ k for b, k in zip(block, key))

    def encrypt_block(self, block):
        """Encrypt a single 16-byte block."""
        print(f"Original block: {block}")
        for round_num in range(32):
            block = self.add_round_key(block, self.key[round_num])
            block = self.substitute(block, round_num)
            print(f"After round {round_num}: {block}")
        block = self.add_round_key(block, self.key[32])
        print(f"Encrypted block: {block}")
        return block

    def decrypt_block(self, block):
        """Decrypt a single 16-byte block."""
        print(f"Encrypted block: {block}")
        block = self.add_round_key(block, self.key[32])
        for round_num in reversed(range(32)):
            block = self.substitute(block, round_num, reverse=True)
            block = self.add_round_key(block, self.key[round_num])
            print(f"After round {round_num}: {block}")
        print(f"Decrypted block: {block}")
        return block

    def encrypt(self, data):
        """Encrypts data in 16-byte blocks."""
        if len(data) % 16 != 0:
            data += b"\x00" * (16 - len(data) % 16)
        return b"".join(self.encrypt_block(data[i:i+16]) for i in range(0, len(data), 16))

    def decrypt(self, data):
        """Decrypts data in 16-byte blocks."""
        return b"".join(self.decrypt_block(data[i:i+16]) for i in range(0, len(data), 16)).rstrip(b"\x00")


def main():
    key = b"simplekey123456"
    data = b"testdata"

    cobra = SimpleCOBRA(key)
    encrypted = cobra.encrypt(data)
    print(f"Encrypted: {encrypted}")

    decrypted = cobra.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()

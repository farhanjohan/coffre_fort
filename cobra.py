import random

class COBRA:
    def __init__(self, key):
        if not isinstance(key, (bytes, bytearray)):
            raise ValueError("Key must be a bytes object.")
        self.key = self.expand_key(key)
        self.s_boxes, self.reverse_s_boxes = self.generate_s_boxes()

    def expand_key(self, key):
        if len(key) < 16:
            key += b"\x00" * (16 - len(key))
        expanded_key = []
        for i in range(33):
            expanded_key.append(self.custom_hash(key + i.to_bytes(1, 'big')))
        return expanded_key

    def custom_hash(self, data, rounds=1000):
        hash_value = sum(data) % 256
        for _ in range(rounds):
            hash_value = (hash_value * 31 + 7) % 256
        return bytes((hash_value + i) % 256 for i in range(16))

    def generate_s_boxes(self):
        s_boxes = []
        reverse_s_boxes = []
        random.seed(42)

        for i in range(4):
            s_box = list(range(16))
            random.shuffle(s_box)
            reverse_s_box = {v: k for k, v in enumerate(s_box)}
            if len(reverse_s_box) != 16:
                raise ValueError(f"Inconsistent reverse S-box at round {i}.")
            s_boxes.append(s_box)
            reverse_s_boxes.append(reverse_s_box)

        return s_boxes, reverse_s_boxes

    def substitute(self, block, round_num, reverse=False):
        s_box = self.reverse_s_boxes[round_num // 8] if reverse else self.s_boxes[round_num // 8]
        substituted = bytearray(block)
        for i in range(len(substituted)):
            lower_nibble = substituted[i] & 0x0F
            upper_nibble = (substituted[i] >> 4) & 0x0F
            substituted[i] = (s_box[lower_nibble] | (s_box[upper_nibble] << 4))
        return substituted

    def feistel(self, block):
        L, R = block[:8], block[8:]
        for _ in range(3):
            temp = R
            R = bytes(l ^ r for l, r in zip(L, self.simple_permutation(R)))
            L = temp
        return L + R

    def simple_permutation(self, block):
        return bytes(((b << 1) | (b >> 7)) & 0xFF for b in block)

    def linear_transform(self, block):
        return bytes((b ^ 0x1F) for b in block)

    def add_round_key(self, block, key):
        return bytes(b ^ k for b, k in zip(block, key))

    def encrypt_block(self, block):
        print(f"Original block: {block}")
        for round_num in range(32):
            block = self.add_round_key(block, self.key[round_num])
            block = self.substitute(block, round_num)
            block = self.feistel(block)
            block = self.linear_transform(block)
            print(f"After round {round_num}: {block}")
        block = self.add_round_key(block, self.key[32])
        print(f"Encrypted block: {block}")
        return block

    def decrypt_block(self, block):
        print(f"Encrypted block: {block}")
        block = self.add_round_key(block, self.key[32])
        for round_num in reversed(range(32)):
            block = self.linear_transform(block)
            block = self.feistel(block)
            block = self.substitute(block, round_num, reverse=True)
            block = self.add_round_key(block, self.key[round_num])
            print(f"After round {round_num}: {block}")
        print(f"Decrypted block: {block}")
        return block

    def encrypt(self, data):
        if len(data) % 16 != 0:
            data += b"\x00" * (16 - len(data) % 16)
        return b"".join(self.encrypt_block(data[i:i+16]) for i in range(0, len(data), 16))

    def decrypt(self, data):
        return b"".join(self.decrypt_block(data[i:i+16]) for i in range(0, len(data), 16)).rstrip(b"\x00")


def main():
    key = b"mysecretkey12345"
    data = b"test."

    cobra = COBRA(key)
    encrypted = cobra.encrypt(data)
    print(f"Encrypted: {encrypted}")

    decrypted = cobra.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()

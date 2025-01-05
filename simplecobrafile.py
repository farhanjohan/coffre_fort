import os
import random


class SimpleCOBRA:
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
        for _ in range(4):
            s_box = list(range(16))
            random.shuffle(s_box)
            reverse_s_box = {v: k for k, v in enumerate(s_box)}
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
        return bytes(substituted)

    def add_round_key(self, block, key):
        return bytes(b ^ k for b, k in zip(block, key))

    def encrypt_block(self, block):
        for round_num in range(32):
            block = self.add_round_key(block, self.key[round_num])
            block = self.substitute(block, round_num)
        return self.add_round_key(block, self.key[32])

    def decrypt_block(self, block):
        block = self.add_round_key(block, self.key[32])
        for round_num in reversed(range(32)):
            block = self.substitute(block, round_num, reverse=True)
            block = self.add_round_key(block, self.key[round_num])
        return block

    def encrypt_file(self, input_path, output_path):
        with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
            while chunk := infile.read(16):
                if len(chunk) < 16:
                    chunk += b"\x00" * (16 - len(chunk))  # Padding
                encrypted_chunk = self.encrypt_block(chunk)
                outfile.write(encrypted_chunk)

    def decrypt_file(self, input_path, output_path):
        with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
            while chunk := infile.read(16):
                decrypted_chunk = self.decrypt_block(chunk)
                outfile.write(decrypted_chunk.rstrip(b"\x00"))
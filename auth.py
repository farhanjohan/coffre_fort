import os
import secrets
import json
from user_management import *
from credentials import *

class ZKPAuth:
    def __init__(self, derived_key, p=23, g=5):
        self.p = p
        self.g = g
        self.cle_privee = derived_key
        self.cle_publique = pow(self.g, self.cle_privee, self.p)

    def generer_preuve(self):
        self.r = secrets.randbelow(self.p - 1)
        self.M = pow(self.g, self.r, self.p)
        return self.M

    def verifier_preuve(self, challenge, preuve):
        gauche = (pow(self.g, preuve, self.p) * pow(self.cle_publique, challenge, self.p)) % self.p
        return gauche == self.M

    def repondre_challenge(self, challenge):
        return (self.r - challenge * self.cle_privee) % (self.p - 1)

def sponge_hash(password, iterations=100000):
    hash_value = sum(ord(char) for char in password) % 256
    for _ in range(iterations):
        hash_value = (hash_value * 31 + 7) % 256
    return hash_value

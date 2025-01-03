import os
import secrets
import json
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID
from cryptography import x509
from user_management import *
from credentials import *
import datetime

# Global CA key pair


if os.path.exists("ca_private_key.pem") and os.path.exists("ca_public_key.pem"):
    with open("ca_private_key.pem", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open("ca_public_key.pem", "rb") as f:
        ca_public_key = serialization.load_pem_public_key(f.read())
    print("CA keys loaded from disk.")
else:
    # Generate and save CA keys
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_public_key = ca_private_key.public_key()

    with open("ca_private_key.pem", "wb") as f:
        f.write(ca_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open("ca_public_key.pem", "wb") as f:
        f.write(ca_public_key.public_bytes(serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))

    print("CA keys saved to disk.")

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

def get_ca_public_key():
    global ca_public_key
    return ca_public_key

def generate_certificate():
    global ca_private_key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Coffre-Fort"),
        x509.NameAttribute(NameOID.COMMON_NAME, "coffre-fort.local"),
    ])
    certificate = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .sign(ca_private_key, hashes.SHA256())

    with open("server_cert.pem", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open("server_key.pem", "wb") as key_file:
        key_file.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    print("Server certificate and key generated.")
    return "server_cert.pem", "server_key.pem"

def verify_certificate(certificate_path, ca_public_key):
    try:
        with open(certificate_path, "rb") as cert_file:
            certificate = load_pem_x509_certificate(cert_file.read())
        # Verify the certificate using the CA public key
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        print("Certificate verified successfully.")
        return True
    except ValueError as e:
        print(f"Error parsing certificate: {e}")
        return False
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False

def sponge_hash(password, iterations=100000):
    hash_value = sum(ord(char) for char in password) % 256
    for _ in range(iterations):
        hash_value = (hash_value * 31 + 7) % 256
    return hash_value

def authenticate_user(username, password):
    user_credentials = load_user_credentials()
    if user_credentials[username]["password"] != password:
        print("Authentification échouée : mot de passe incorrect.")
        return False
    if not os.path.exists("server_cert.pem"):
        print("Certificate not found. Generating a new one...")
        generate_certificate()

    cert_path = "server_cert.pem"
    ca_public_key = get_ca_public_key()

    if not verify_certificate(cert_path, ca_public_key):
        print("Authentication failed: Certificate verification unsuccessful.")
        return False

    derived_key = sponge_hash(password)
    zkp = ZKPAuth(derived_key)
    print(f"Clé publique : {zkp.cle_publique}")

    M = zkp.generer_preuve()
    print(f"Engagement (M): {M}")
    challenge = secrets.randbelow(zkp.p - 1)
    print(f"Challenge: {challenge}")
    preuve = zkp.repondre_challenge(challenge)
    print(f"Preuve: {preuve}")
    verification = zkp.verifier_preuve(challenge, preuve)

    if verification:
        print("Authentication successful.")
        return True
    else:
        print("Authentication failed.")
        return False

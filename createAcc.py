import user_management
import derivation

username = input("Entrez un nom d'utilisateur : ")
password = input("Entrez le mot de passe : ")
user_management.create_account(username, password)
# 2) Dérivation de la clé (KDF)
derived_key = derivation.derive_key(password)
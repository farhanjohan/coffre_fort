import random
import user_management
import derivation
import echange

def main():
    # 1) Enrollement
    user_management.create_account()

    # 2) Dérivation de la clé (KDF)
    derivation.derive_key()

    # 3) authentification double sens

    # 4) echange cles secret
    p = 23 ###### on peut changer 
    g = 5

    





if __name__ == "__main__":
    main()



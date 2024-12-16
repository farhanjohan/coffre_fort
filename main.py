import user_management
import derivation

def main():
    # 1) Enrollement
    user_management.create_account()

    # 2) Dérivation de la clé (KDF)
    derivation.derive_key()



if __name__ == "__main__":
    main()



import random
import user_management
import derivation
import echange
import server
import socket

def main():

    #### connection ####

    #  Enrollement
    user_management.create_account()

    # Dérivation de la clé (KDF)
    derivation.derive_key()

    #  authentification double sens

    #  echange cles secret
    p = 23 ###### on peut changer 
    g = 5

    





if __name__ == "__main__":
    main()



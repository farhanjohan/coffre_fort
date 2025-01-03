import random
import user_management
import derivation
import echange
import connect

def main():

    #### connection ####
    connect.server_connect("25.15.154.124","6000")



    ##### echange cle secret ######
    echange.echange_cles_server()
    

if __name__ == "__main__":
    main()



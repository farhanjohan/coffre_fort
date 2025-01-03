import connect
import echange


def main():

    #### connection ###
    connect.client_connect("","")

    ##### ehchange cle secret #####
    echange.echange_cles_client()

if __name__ == "__main__":
    main()
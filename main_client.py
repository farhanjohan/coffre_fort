import connect
import echange


def main():

    #### connection ###
    connect.client_connect("25.15.154.124","")

    ##### ehchange cle secret #####
    echange.echange_cles_client()

if __name__ == "__main__":
    main()
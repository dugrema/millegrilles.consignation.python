#!/usr/bin/python3

# Module qui permet de demarrer les appareils sur un Raspberry Pi
import traceback
from millegrilles.noeuds.Noeud import DemarreurNoeud


# **** MAIN ****
def main():
    try:
        demarreur.parse()
        demarreur.executer_daemon_command()
    except Exception as e:
        print("!!! ******************************")
        print("MAIN: Erreur %s" % str(e))
        traceback.print_exc()
        print("!!! ******************************")
        demarreur.print_help()


if __name__ == "__main__":
    demarreur = DemarreurNoeud()
    main()

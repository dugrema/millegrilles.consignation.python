import signal

from millegrilles.processus.MGProcessus import MGPProcessusControleur

# --- MAIN ---
controleur = MGPProcessusControleur()

def exit_gracefully(signum, frame):
    print("Arret de MGProcessusControleur")
    controleur.deconnecter()

def main():

    print("Demarrage de MGProcessusControleur")

    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    controleur.initialiser()

    try:
        print("MGProcessusControleur est pret")
        controleur.executer()
    finally:
        exit_gracefully(None, None)

    print("MGProcessusControleur est arrete")

if __name__=="__main__":
    main()

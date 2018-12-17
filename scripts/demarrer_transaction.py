import signal

from millegrilles.transaction.ConsignateurTransaction import ConsignateurTransaction

consignateur = ConsignateurTransaction()


def exit_gracefully(signum, frame):
    print("Arret de OrienteurTransaction")
    consignateur.deconnecter()


def main():

    print("Demarrage de ConsignateurTransaction")

    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    consignateur.configurer()

    try:
        print("ConsignateurTransaction est pret")
        consignateur.executer()
    finally:
        print("Arret de ConsignateurTransaction")
        consignateur.deconnecter()

    print("ConsignateurTransaction est arrete")


if __name__=="__main__":
    main()

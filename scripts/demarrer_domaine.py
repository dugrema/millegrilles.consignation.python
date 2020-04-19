#!/usr/bin/python3
# Utiliser ce script pour demarrer des gestionnaires de domaines MilleGrilles
import os

from millegrilles.Domaines import GestionnaireDomainesMilleGrilles


if __name__ == '__main__':
    keycert_file = GestionnaireDomainesMilleGrilles.preparer_mongo_keycert()
    try:
        gestionnaire = GestionnaireDomainesMilleGrilles()
        gestionnaire.main()
    finally:
        os.remove(keycert_file)


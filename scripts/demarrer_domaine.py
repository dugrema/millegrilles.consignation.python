#!/usr/bin/python3
# Utiliser ce script pour demarrer des gestionnaires de domaines MilleGrilles
from millegrilles.Domaines import GestionnaireDomainesMilleGrilles


if __name__ == '__main__':
    GestionnaireDomainesMilleGrilles.preparer_mongo_keycert()
    gestionnaire = GestionnaireDomainesMilleGrilles()
    gestionnaire.main()


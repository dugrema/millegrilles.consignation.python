from millegrilles.Declencheur import Declencheur
from mgdomaines.appareils.SenseursPassifs import SenseursPassifsConstantes
import datetime
import argparse


class DeclencheurAppareils(Declencheur):

    NOM_DOMAINE = 'mgdomaines.appareils'

    def __init__(self):
        super().__init__()
        self.parser = argparse.ArgumentParser(description="Declencher un processus MilleGrilles")
        self.parser.add_argument('-m', type=str, nargs=1, required=True, help="Methode a declencher")

    def senseurspassifs_maj_horaire(self):
        domaine = '%s.%s' % (self.NOM_DOMAINE, 'SenseursPassifs.MAJHoraire')
        dict_message = {
            'evenements': SenseursPassifsConstantes.EVENEMENT_MAJ_HORAIRE,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        self.transmettre_declencheur_domaine(domaine, dict_message)

    def senseurspassifs_maj_quotidienne(self):
        domaine = '%s.%s' % (self.NOM_DOMAINE, 'SenseursPassifs.MAJQuotidienne')
        dict_message = {
            'evenements': SenseursPassifsConstantes.EVENEMENT_MAJ_QUOTIDIENNE,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        self.transmettre_declencheur_domaine(domaine, dict_message)

    def executer_methode(self):
        args = self.parser.parse_args()
        methode_declencheur = getattr(self, args.m[0])
        # Executer la methode
        methode_declencheur()


# **** MAIN ****
DeclencheurAppareils().executer_methode()

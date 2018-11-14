# Module de Processus a utiliser pour tester MilleGrilles
from millegrilles.processus.MGProcessus import MGProcessus
from millegrilles import Constantes
import time


class TestOrienteur(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self._initiale_executee = False # Utilise par unit tests

    def initiale(self):
        print("Etape initiale executee avec evenement: %s" % self._evenement)
        self._initiale_executee = True
        self.set_etape_suivante(TestOrienteur.etape1.__name__)

        # Implicitement l'etape devrait etre enregistree dans le document de processus
        return {'texte': 'La methode initiale de ProcessusTest est completee'}

    def etape1(self):
        self.set_etape_suivante(TestOrienteur.etape2.__name__)

        # Implicitement l'etape devrait etre enregistree dans le document de processus
        return {
            'nombre': 123,
            'dict_donnees': {
                'greetings': 'allo',
                'calcul': 123.948
            }
        }

    def etape2(self):
        self.set_etape_suivante() # Etape finale par defaut

        # Implicitement l'etape devrait etre enregistree dans le document de processus
        return {
            'epoch': int(time.time()),
            'nombre': 234,
            'etape-courante-evenement': self._document_processus[Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE]
        }

    #def finale(self): #Noter que l'etape finale est deja implementee dans MGProcessus
        #super().finale(self)
# Module de Processus a utiliser pour tester MilleGrilles
from millegrilles.processus.MGProcessus import MGProcessus

class TestOrienteur(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self._initiale_executee = False

    def initiale(self):
        print("Etape initiale executee avec evenement: %s" % self._evenement)
        self._initiale_executee = True
        self._etape_executee = True
        self._etape_suivante = 'finale'

        return None # Implicitement l'etape devrait etre enregistree dans le document de processus


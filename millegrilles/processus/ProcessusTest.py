# Module de Processus a utiliser pour tester MilleGrilles
from millegrilles.processus.MGProcessus import MGProcessus

class TestOrienteur(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self._initiale_executee = False

    def initiale(self):
        print("Etape initiale executee avec evenement: %s" % self._evenement)
        self._initiale_executee = True
        self.set_etape_suivante() # Set etape suivante, par defaut utilise finale

        # Implicitement l'etape devrait etre enregistree dans le document de processus
        return {'texte': 'La methode initiale de ProcessusTest est completee'}


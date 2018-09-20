# Module pour les processus de Senseur

from millegrilles.processus.MGProcessus import MGProcessus

class ConserverLectureCourante(MGProcessus):

    def __init__(self):
        super().__init__()

    def initiale(self):
        # Executer validation du contenu de la lecture
        erreur_donnees = False
        if erreur_donnees:
            self.set_etape_suivante(ConserverLectureCourante.erreur_fatale.__name__)
            return {"erreurs": "Erreurs identifiees dans les donnees"}

        self.set_etape_suivante(ConserverLectureCourante.sauvegarder_lecture.__name__)

    def sauvegarder_lecture(self):
        self.set_etape_suivante()


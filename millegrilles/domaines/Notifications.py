# Module du domaine des notifications.

from millegrilles.Domaines import GestionnaireDomaine

class GestionnaireNotifications(GestionnaireDomaine):

    def __init__(self, contexte):
        super().__init__(contexte=contexte)


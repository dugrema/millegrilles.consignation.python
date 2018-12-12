# Module du domaine des notifications.

from millegrilles.Domaines import GestionnaireDomaine

class GestionnaireNotifications(GestionnaireDomaine):

    def __init__(self):
        super().__init__(configration, message_dao, document_dao)
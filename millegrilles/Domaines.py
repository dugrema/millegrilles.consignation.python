# Module avec utilitaires generiques pour mgdomaines
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.DocumentDAO import MongoDAO


# Le gestionnaire de domaine est une superclasse qui definit le cycle de vie d'un domaine.
class GestionnaireDomaine:

    def __init__(self):
        self.configuration = None
        self.message_dao = None
        self.document_dao = None

    ''' L'initialisation connecte RabbitMQ, MongoDB, lance la configuration '''
    def initialiser(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()
        self.message_dao = PikaDAO(self.configuration)
        self.document_dao = MongoDAO(self.configuration)

    ''' Configure les comptes, queues/bindings (RabbitMQ), bases de donnees (MongoDB), etc. '''
    def configurer(self):
        pass

    ''' Identifie les transactions qui ont ete persistees pendant que le gestionnaire est hors ligne. '''
    def traiter_backlog(self):
        pass

    ''' Demarre le traitement des messages pour le domaine '''
    def demarrer_traitement_messages(self):
        pass

    ''' Arrete le traitement des messages pour le domaine '''
    def arreter_traitement_messages(self):
        pass

    ''' Permet de deconnecter les DAOs, fermer le gestionnaire. '''
    def deconnecter(self):
        pass

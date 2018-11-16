# Module avec utilitaires generiques pour mgdomaines
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO, JSONHelper
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.processus.MGProcessus import MGPProcessusDemarreur


# Le gestionnaire de domaine est une superclasse qui definit le cycle de vie d'un domaine.
class GestionnaireDomaine:

    def __init__(self):
        self.configuration = None
        self.message_dao = None
        self.document_dao = None
        self.demarreur_processus = None
        self.json_helper = JSONHelper()

    ''' L'initialisation connecte RabbitMQ, MongoDB, lance la configuration '''
    def initialiser(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()
        self.message_dao = PikaDAO(self.configuration)
        self.document_dao = MongoDAO(self.configuration)

        self.document_dao.connecter()
        self.message_dao.connecter()

        self.demarreur_processus = MGPProcessusDemarreur(self.message_dao, self.document_dao)

    ''' Configure les comptes, queues/bindings (RabbitMQ), bases de donnees (MongoDB), etc. '''
    def configurer(self):
        pass

    ''' Identifie les transactions qui ont ete persistees pendant que le gestionnaire est hors ligne. '''
    def traiter_backlog(self):
        pass

    ''' Demarre le traitement des messages pour le domaine '''
    def demarrer_traitement_messages_blocking(self, queue_name):
        self.message_dao.channel.basic_consume(self.traiter_transaction, queue=queue_name, no_ack=False)
        try:
            self.message_dao.channel.start_consuming()
        except OSError as oserr:
            print("erreur start_consuming, probablement du a la fermeture de la queue: %s" % oserr)

    def traiter_transaction(self, ch, method, properties, body):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    ''' Arrete le traitement des messages pour le domaine '''
    def arreter_traitement_messages(self):
        pass

    ''' Permet de deconnecter les DAOs, fermer le gestionnaire. '''
    def deconnecter(self):
        self.document_dao.deconnecter()
        self.message_dao.deconnecter()

    def demarrer_processus(self, processus, parametres):
        self.demarreur_processus.demarrer_processus(processus, parametres)


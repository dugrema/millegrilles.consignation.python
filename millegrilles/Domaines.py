# Module avec utilitaires generiques pour mgdomaines
from millegrilles.dao.MessageDAO import JSONHelper
from millegrilles.processus.MGProcessus import MGPProcessusDemarreur
from millegrilles.util.UtilScriptLigneCommande import ModeleAvecDocumentMessageDAO

import logging


# Le gestionnaire de domaine est une superclasse qui definit le cycle de vie d'un domaine.
class GestionnaireDomaine(ModeleAvecDocumentMessageDAO):

    def __init__(self):
        super().__init__()
        self.demarreur_processus = None
        self.json_helper = JSONHelper()
        self._logger = logging.getLogger("%s.GestionnaireDomaine" % __name__)

    ''' L'initialisation connecte RabbitMQ, MongoDB, lance la configuration '''
    def initialiser(self):
        super().initialiser()
        self.connecter()  # On doit se connecter immediatement pour permettre l'appel a configurer()

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
            self._logger.error("erreur start_consuming, probablement du a la fermeture de la queue: %s" % oserr)

    def traiter_transaction(self, ch, method, properties, body):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    ''' Arrete le traitement des messages pour le domaine '''
    def arreter_traitement_messages(self):
        pass

    def demarrer_processus(self, processus, parametres):
        self.demarreur_processus.demarrer_processus(processus, parametres)

    '''
    Implementer cette methode pour retourner le nom de la queue.
    
    :returns: Nom de la Q a ecouter.
    '''
    def get_nom_queue(self):
        raise NotImplementedError("Methode non-implementee")

    '''
    Methode qui peut etre invoquee pour demarrer l'execution du gestionnaire.
    '''
    def executer_gestionnaire(self):
        self.main()

    def executer(self):
        # Doit creer le demarreur ici parce que la connexion a Mongo n'est pas prete avant
        self.demarreur_processus = MGPProcessusDemarreur(self.message_dao, self.document_dao)

        try:
            self.traiter_backlog()
            self.demarrer_traitement_messages_blocking(self.get_nom_queue())
        except Exception as e:
            logging.exception("Interruption du gestionnaire, erreur: %s" % str(e))

    def exit_gracefully(self, signum=None, frame=None):
        self._logger.warning("Arret de MGProcessusControleur, signal=%s" % str(signum))
        self.arreter_traitement_messages()
        super().exit_gracefully(signum, frame)

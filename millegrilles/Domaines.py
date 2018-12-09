# Module avec utilitaires generiques pour mgdomaines
from millegrilles.dao.MessageDAO import JSONHelper
from millegrilles.processus.MGProcessus import MGPProcessusDemarreur
from millegrilles.util.UtilScriptLigneCommande import ModeleAvecDocumentMessageDAO

import logging
from threading import Thread, Event


class GestionnaireDomainesMilleGrilles(ModeleAvecDocumentMessageDAO):
    """
    Classe qui agit comme gestionnaire centralise de plusieurs domaines MilleGrilles.
    Cette classe s'occupe des DAOs et du cycle de vie du programme.
    """

    def __init__(self):
        super().__init__()
        self._logger = logging.getLogger("%s.GestionnaireDomainesMilleGrilles" % __name__)
        self._gestionnaires = []
        self._stop_event = Event()

    def initialiser(self):
        """ L'initialisation connecte RabbitMQ, MongoDB, lance la configuration """
        super().initialiser()
        self.connecter()  # On doit se connecter immediatement pour permettre l'appel a configurer()

    def configurer_parser(self):
        super().configurer_parser()

        self.parser.add_argument(
            'domaines',
            type=str,
            help="Gestionnaires de domaines a charger. Format: nom_module1:nom_classe1,nom_module2:nom_classe2,[...]"
        )

        self.parser.add_argument(
            '--debug', action="store_true", required=False,
            help="Active le debugging (logger, tres verbose)"
        )

        self.parser.add_argument(
            '--info', action="store_true", required=False,
            help="Afficher davantage de messages (verbose)"
        )

    ''' Charge les domaines listes en parametre '''
    def charger_domaines(self):

        liste_domaines = self.args.domaines
        gestionnaires = liste_domaines.split(',')
        self._logger.info("Chargement des gestionnaires: %s" % str(gestionnaires))

        for gestionnaire in gestionnaires:
            noms_module_class = gestionnaire.strip().split(':')
            nom_module = noms_module_class[0]
            nom_classe = noms_module_class[1]

            self._logger.debug("Nom package: %s, Classe: %s" % (nom_module, nom_classe))

            classe_processus = __import__(nom_module, fromlist=[nom_classe])
            classe = getattr(classe_processus, nom_classe)

            # Preparer une instance du gestionnaire
            instance = classe(self.configuration, self.message_dao, self.document_dao)
            instance.configurer()  # Executer la configuration du gestionnaire de domaine
            self._gestionnaires.append(instance)

    def demarrer_execution_domaines(self):
        for gestionnaire in self._gestionnaires:
            gestionnaire.demarrer()

    def exit_gracefully(self, signum=None, frame=None):
        self._logger.info("Arret du gestionnaire de domaines MilleGrilles")
        self._stop_event.set()  # Va arreter la boucle de verification des gestionnaires

        # Avertir chaque gestionnaire
        for gestionnaire in self._gestionnaires:
            try:
                gestionnaire.arreter()
            except Exception as e:
                self._logger.warning("Erreur arret gestionnaire %s: %s" % (gestionnaire.__name__, str(e)))

        super().exit_gracefully()

    def executer(self):

        self.set_logging_level()

        self.charger_domaines()

        self.demarrer_execution_domaines()

        # Surveiller les gestionnaires - si un gestionnaire termine son execution, on doit tout fermer
        while not self._stop_event.is_set():

            self._stop_event.wait(20)  # Boucler toutes les 20 secondes

    def set_logging_level(self):
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            logging.getLogger('mgdomaines').setLevel(logging.INFO)
            logging.getLogger('millegrilles').setLevel(logging.INFO)
        elif self.args.info:
            self._logger.setLevel(logging.INFO)
            logging.getLogger('mgdomaines').setLevel(logging.INFO)


class GestionnaireDomaine:
    """ Le gestionnaire de domaine est une superclasse qui definit le cycle de vie d'un domaine. """

    def __init__(self, configuration, message_dao, document_dao):
        self.configuration = configuration
        self.message_dao = message_dao
        self.document_dao = document_dao

        self.demarreur_processus = None
        self.json_helper = JSONHelper()
        self._logger = logging.getLogger("%s.GestionnaireDomaine" % __name__)
        self._thread = None

    # ''' L'initialisation connecte RabbitMQ, MongoDB, lance la configuration '''
    # def initialiser(self):
    #     self.connecter()  # On doit se connecter immediatement pour permettre l'appel a configurer()

    def configurer(self):
        """ Configure les comptes, queues/bindings (RabbitMQ), bases de donnees (MongoDB), etc. """
        pass

    def demarrer(self):
        """ Demarrer une thread pour ce gestionnaire """
        self._thread = Thread(target=self.executer())
        self._thread.start()

    def traiter_backlog(self):
        """ Identifie les transactions qui ont ete persistees pendant que le gestionnaire est hors ligne. """
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

    def executer(self):
        # Doit creer le demarreur ici parce que la connexion a Mongo n'est pas prete avant
        self.demarreur_processus = MGPProcessusDemarreur(self.message_dao, self.document_dao)

        try:
            self.traiter_backlog()
            self.demarrer_traitement_messages_blocking(self.get_nom_queue())
        except Exception as e:
            logging.exception("Interruption du gestionnaire, erreur: %s" % str(e))

    def arreter(self):
        self._logger.warning("Arret de GestionnaireDomaine")
        self.arreter_traitement_messages()

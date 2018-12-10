# Module avec utilitaires generiques pour mgdomaines
from millegrilles.dao.MessageDAO import JSONHelper
from millegrilles.processus.MGProcessus import MGPProcessusDemarreur
from millegrilles.util.UtilScriptLigneCommande import ModeleAvecDocumentMessageDAO

import logging
import json

from pika.exceptions import ChannelClosed

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
            '--domaines',
            type=str,
            required=False,
            help="Gestionnaires de domaines a charger. Format: nom_module1:nom_classe1,nom_module2:nom_classe2,[...]"
        )

        self.parser.add_argument(
            '--configuration',
            type=str,
            required=False,
            help="Chemin du fichier de configuration des domaines"
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

        liste_classes_gestionnaires = []

        # Faire liste des domaines args
        liste_domaines = self.args.domaines
        if liste_domaines is not None:
            gestionnaires = liste_domaines.split(',')
            self._logger.info("Chargement des gestionnaires: %s" % str(gestionnaires))

            for gestionnaire in gestionnaires:
                noms_module_class = gestionnaire.strip().split(':')
                nom_module = noms_module_class[0]
                nom_classe = noms_module_class[1]
                classe = self.importer_classe_gestionnaire(nom_module, nom_classe)
                liste_classes_gestionnaires.append(classe)

        # Charger le fichier de configuration json
        chemin_fichier_configuration = self.args.configuration
        if chemin_fichier_configuration is None:
            chemin_fichier_configuration = self.configuration.domaines_json

        if chemin_fichier_configuration is not None:
            self._logger.info("Charger la configuration a partir du fichier: %s" % chemin_fichier_configuration)

            with open(chemin_fichier_configuration) as json_config:
                configuration_json = json.load(json_config)

            domaines = configuration_json['domaines']
            for domaine in domaines:
                classe = self.importer_classe_gestionnaire(
                    domaine['module'],
                    domaine['classe']
                )
                liste_classes_gestionnaires.append(classe)

        self._logger.info("%d classes de gestionnaires a charger" % len(liste_classes_gestionnaires))

        # On prepare et configure une instance de chaque gestionnaire
        for classe_gestionnaire in liste_classes_gestionnaires:
            # Preparer une instance du gestionnaire
            instance = classe_gestionnaire(self.configuration, self.message_dao, self.document_dao)
            instance.configurer()  # Executer la configuration du gestionnaire de domaine
            self._gestionnaires.append(instance)

    def importer_classe_gestionnaire(self, nom_module, nom_classe):
        self._logger.info("Nom package: %s, Classe: %s" % (nom_module, nom_classe))
        classe_processus = __import__(nom_module, fromlist=[nom_classe])
        classe = getattr(classe_processus, nom_classe)
        self._logger.debug("Classe gestionnaire chargee: %s %s" % (classe.__module__, classe.__name__))
        return classe

    def demarrer_execution_domaines(self):
        for gestionnaire in self._gestionnaires:
            self._logger.debug("Demarrer un gestionnaire")
            gestionnaire.demarrer()

    def exit_gracefully(self, signum=None, frame=None):
        self._logger.info("Arret du gestionnaire de domaines MilleGrilles")
        self._stop_event.set()  # Va arreter la boucle de verification des gestionnaires

        # Avertir chaque gestionnaire
        for gestionnaire in self._gestionnaires:
            try:
                gestionnaire.arreter()
            except ChannelClosed as ce:
                self._logger.debug("Channel already closed: %s" % str(ce))
            except Exception as e:
                self._logger.warning("Erreur arret gestionnaire %s: %s" % (gestionnaire.__name__, str(e)))

        super().exit_gracefully()

    def executer(self):

        self.set_logging_level()

        self.charger_domaines()

        if len(self._gestionnaires) > 0:
            self.demarrer_execution_domaines()
        else:
            self._stop_event.set()
            self._logger.fatal("Aucun gestionnaire de domaine n'a ete charge. Execution interrompue.")

        # Surveiller les gestionnaires - si un gestionnaire termine son execution, on doit tout fermer
        while not self._stop_event.is_set():

            self._stop_event.wait(20)  # Boucler toutes les 20 secondes

    def set_logging_level(self):
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            logging.getLogger('mgdomaines').setLevel(logging.DEBUG)
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
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
        self.connexion_mq = None
        self.channel_mq = None
        self._arret_en_cours = False
        self._stop_event = Event()

        # ''' L'initialisation connecte RabbitMQ, MongoDB, lance la configuration '''
    # def initialiser(self):
    #     self.connecter()  # On doit se connecter immediatement pour permettre l'appel a configurer()

    def configurer(self):
        """ Configure les comptes, queues/bindings (RabbitMQ), bases de donnees (MongoDB), etc. """
        pass

    def demarrer(self):
        """ Demarrer une thread pour ce gestionnaire """
        self._logger.debug("Debut thread gestionnaire %s" % self.__class__.__name__)
        self._thread = Thread(target=self.executer)
        self._thread.start()
        self._logger.debug("Debut demarree pour gestionnaire %s" % self.__class__.__name__)

    def traiter_backlog(self):
        """ Identifie les transactions qui ont ete persistees pendant que le gestionnaire est hors ligne. """
        pass

    ''' Demarre le traitement des messages pour le domaine '''
    def demarrer_traitement_messages_blocking(self, queue_name):
        with self.message_dao.connecter(separer=True) as connexion_mq:
            self.connexion_mq = connexion_mq  # Garde une copie pour permettre de fermer de l'exterieur
            self.channel_mq = connexion_mq.channel()
            try:
                self.channel_mq.basic_consume(self.traiter_transaction, queue=queue_name, no_ack=False)
                self._logger.info("Debut ecoute sur queue %s" % queue_name)
                self.channel_mq.start_consuming()

                if not self._arret_en_cours:
                    self._logger.warning("Retour de queue %s start_consuming()" % queue_name)
            except OSError as oserr:
                if not self._arret_en_cours:
                    self._logger.exception(
                        "erreur start_consuming, probablement du a la fermeture de la queue: %s" % str(oserr)
                    )
        self.channel_mq = None
        self.connexion_mq = None

    def traiter_transaction(self, ch, method, properties, body):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    ''' Arrete le traitement des messages pour le domaine '''
    def arreter_traitement_messages(self):
        self._arret_en_cours = True
        self._stop_event.set()
        if self.channel_mq is not None:
            self.channel_mq.close()

    def demarrer_processus(self, processus, parametres):
        self.demarreur_processus.demarrer_processus(processus, parametres)

    '''
    Implementer cette methode pour retourner le nom de la queue.
    
    :returns: Nom de la Q a ecouter.
    '''
    def get_nom_queue(self):
        raise NotImplementedError("Methode non-implementee")

    def executer(self):
        self._logger.info("Debut execution gestionnaire de domaine %s" % self.__class__.__name__)
        # Doit creer le demarreur ici parce que la connexion a Mongo n'est pas prete avant
        self.demarreur_processus = MGPProcessusDemarreur(self.message_dao, self.document_dao)

        self.traiter_backlog()
        while not self._stop_event.is_set():
            try:
                self.demarrer_traitement_messages_blocking(self.get_nom_queue())
            except Exception as e:
                self._logger.exception(
                    "Erreur durant reception message - on va tenter de se reconnecter: %s" % str(e)
                )
                if not self._stop_event.is_set():
                    self._stop_event.wait(30)

        # Indiquer au gestionnaire millegrilles que ce domaine a termine

    def arreter(self):
        self._logger.warning("Arret de GestionnaireDomaine")
        self.arreter_traitement_messages()

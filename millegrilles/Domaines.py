# Module avec utilitaires generiques pour mgdomaines
from millegrilles.dao.MessageDAO import JSONHelper
from millegrilles.processus.MGProcessus import MGPProcessusDemarreur
from millegrilles.util.UtilScriptLigneCommande import ModeleAvecDocumentMessageDAO
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles

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
                self._logger.debug("Channel deja ferme: %s" % str(ce))
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
            self.message_dao.start_consuming()  # Blocking
            self._logger.debug("Erreur consuming, attendre 5 secondes pour ressayer")

            self._stop_event.wait(5)  # Boucler toutes les 20 secondes

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

    def __init__(self, configuration=None, message_dao=None, document_dao=None, contexte=None):

        # Nouvelle approche, utilisation classe contexte pour obtenir les ressources
        self._contexte = contexte
        if contexte is None:
            self._contexte = ContexteRessourcesMilleGrilles(configuration, message_dao, document_dao)

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
        self.demarreur_processus = MGPProcessusDemarreur(self.message_dao, self.document_dao)

    def demarrer(self):
        """ Demarrer une thread pour ce gestionnaire """
        self._logger.debug("Debut thread gestionnaire %s" % self.__class__.__name__)
        self.configurer()
        self.traiter_backlog()
        self._logger.info("Backlog traite, on enregistre la queue %s" % self.get_nom_queue())
        self.enregistrer_queue(self.get_nom_queue())

    def traiter_backlog(self):
        """ Identifie les transactions qui ont ete persistees pendant que le gestionnaire est hors ligne. """
        pass

    ''' Demarre le traitement des messages pour le domaine '''
    def enregistrer_queue(self, queue_name):
        self._logger.info("Enregistrement queue %s" % queue_name)
        self.message_dao.enregistrer_callback(queue=queue_name, callback=self.traiter_transaction)

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

    def arreter(self):
        self._logger.warning("Arret de GestionnaireDomaine")
        self.arreter_traitement_messages()

    @property
    def configuration(self):
        return self._contexte.configuration

    @property
    def message_dao(self):
        return self._contexte.message_dao

    @property
    def document_dao(self):
        return self._contexte.document_dao

    @property
    def contexte(self):
        return self._contexte

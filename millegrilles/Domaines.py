# Module avec utilitaires generiques pour mgdomaines
from millegrilles import Constantes
from millegrilles.dao.MessageDAO import JSONHelper
from millegrilles.dao.DocumentDAO import MongoJSONEncoder
from millegrilles.MGProcessus import MGPProcessusDemarreur, MGPProcesseurTraitementEvenements
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles

import logging
import json
import datetime

from pika.exceptions import ChannelClosed
from pymongo.errors import OperationFailure

from threading import Thread, Event


class GestionnaireDomainesMilleGrilles(ModeleConfiguration):
    """
    Classe qui agit comme gestionnaire centralise de plusieurs domaines MilleGrilles.
    Cette classe s'occupe des DAOs et du cycle de vie du programme.
    """

    def __init__(self):
        super().__init__()
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))
        self._gestionnaires = []
        self._stop_event = Event()
        self.__mq_ioloop = None

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        """ L'initialisation connecte RabbitMQ, MongoDB, lance la configuration """
        super().initialiser(init_document, init_message, connecter)
        self.__mq_ioloop = Thread(name="MQ-ioloop", target=self.contexte.message_dao.run_ioloop)
        self.__mq_ioloop.start()

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
            chemin_fichier_configuration = self.contexte.configuration.domaines_json

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
            instance = classe_gestionnaire(self.contexte)
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
        self.arreter()
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
            # self.contexte.message_dao.start_consuming()  # Blocking
            # self._logger.debug("Erreur consuming, attendre 5 secondes pour ressayer")

            self._stop_event.wait(60)   # Boucler pour maintenance  A FAIRE

        self._logger.info("Fin de la boucle executer() dans MAIN")

    def arreter(self):
        self._logger.info("Arret du gestionnaire de domaines MilleGrilles")
        self._stop_event.set()  # Va arreter la boucle de verification des gestionnaires

        # Avertir chaque gestionnaire
        for gestionnaire in self._gestionnaires:
            try:
                gestionnaire.arreter()
            except ChannelClosed as ce:
                self._logger.debug("Channel deja ferme: %s" % str(ce))
            except Exception as e:
                self._logger.warning("Erreur arret gestionnaire %s: %s" % (gestionnaire.__class__.__name__, str(e)))

        self.deconnecter()

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

    def __init__(self, contexte):

        # Nouvelle approche, utilisation classe contexte pour obtenir les ressources
        self._contexte = contexte
        self.demarreur_processus = None
        self.json_helper = JSONHelper()
        self._logger = logging.getLogger("%s.GestionnaireDomaine" % __name__)
        self._thread = None
        self._watchers = list()
        self.connexion_mq = None
        self.channel_mq = None
        self._arret_en_cours = False
        self._stop_event = Event()
        self.traitement_evenements = None

        # ''' L'initialisation connecte RabbitMQ, MongoDB, lance la configuration '''
    # def initialiser(self):
    #     self.connecter()  # On doit se connecter immediatement pour permettre l'appel a configurer()

    def configurer(self):
        self.traitement_evenements = MGPProcesseurTraitementEvenements(self._contexte, gestionnaire_domaine=self)
        self.traitement_evenements.initialiser([self.get_collection_processus_nom()])
        """ Configure les comptes, queues/bindings (RabbitMQ), bases de donnees (MongoDB), etc. """
        self.demarreur_processus = MGPProcessusDemarreur(
            self.contexte, self.get_nom_domaine(), self.get_collection_transaction_nom(),
            self.get_collection_processus_nom(), self.traitement_evenements)

    def demarrer(self):
        """ Demarrer une thread pour ce gestionnaire """
        self._logger.debug("Debut thread gestionnaire %s" % self.__class__.__name__)
        self.configurer()
        self.traiter_backlog()
        self._logger.info("Backlog traite, on enregistre la queue %s" % self.get_nom_queue())
        self.contexte.message_dao.register_channel_listener(self)

    def traiter_backlog(self):
        """ Identifie les transactions qui ont ete persistees pendant que le gestionnaire est hors ligne. """
        pass

    def on_channel_open(self, channel):
        """
        Callback pour l"ouverture ou la reouverture du channel MQ
        :param channel:
        :return:
        """
        self.channel_mq = channel
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self.setup_rabbitmq(channel)

    def setup_rabbitmq(self, channel):
        """ Callback pour faire le setup de rabbitMQ quand le channel est ouvert """
        pass

    def on_channel_close(self, channel=None, code=None, reason=None):
        """
        Callback pour la fermeture du channel
        :param channel:
        :return:
        """
        self._logger.info("Channel ferme: %s, %s" %(code, reason))
        self.channel_mq = None

    def inscrire_basicconsume(self, queue, callback):
        nom_queue = queue.method.queue
        self._logger.info("Queue prete, on enregistre basic_consume %s" % nom_queue)
        self.channel_mq.basic_consume(callback, queue=nom_queue, no_ack=False)

    def callback_queue_transaction(self, queue):
        """
        Suite d'un queue_declare, active le basic_consume sur la Q en utilisant la methode self.traiter_transaction.
        :param queue:
        :return:
        """
        nom_queue = queue.method.queue
        self._logger.info("Queue prete, on enregistre basic_consume %s" % nom_queue)
        self.channel_mq.basic_consume(self.traiter_transaction, queue=nom_queue, no_ack=False)

    def callback_queue_requete_noeud(self, queue):
        """
        Suite d'un queue_declare, active le basic_consume sur la Q en utilisant la methode self.traiter_transaction.
        :param queue:
        :return:
        """
        nom_queue = queue.method.queue
        self._logger.info("Queue prete, on enregistre basic_consume %s" % nom_queue)
        self.channel_mq.basic_consume(self.traiter_requete_noeud, queue=nom_queue, no_ack=False)

    def callback_queue_requete_inter(self, queue):
        """
        Suite d'un queue_declare, active le basic_consume sur la Q en utilisant la methode self.traiter_transaction.
        :param queue:
        :return:
        """
        nom_queue = queue.method.queue
        self._logger.info("Queue prete, on enregistre basic_consume %s" % nom_queue)
        self.channel_mq.basic_consume(self.traiter_requete_inter, queue=nom_queue, no_ack=False)

    def demarrer_watcher_collection(self, nom_collection_mongo: str, routing_key: str):
        """
        Enregistre un watcher et demarre une thread qui lit le pipeline dans MongoDB. Les documents sont
        lus au complet et envoye avec la routing_key specifiee.
        :param nom_collection_mongo: Nom de la collection dans MongoDB pour cette MilleGrille
        :param routing_key: Nom du topic a enregistrer,
               e.g. noeuds.source.millegrilles_domaines_SenseursPassifs.affichage.__nom_noeud__.__no_senseur__
        :return:
        """
        watcher = WatcherCollectionMongoThread(self.contexte, self._stop_event, nom_collection_mongo, routing_key)
        self._watchers.append(watcher)
        watcher.start()

    def traiter_transaction(self, ch, method, properties, body):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    def traiter_requete_noeud(self, ch, method, properties, body):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    def traiter_requete_inter(self, ch, method, properties, body):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    def traiter_cedule(self, message):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    def get_collection_transaction_nom(self):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    def get_collection_processus_nom(self):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    def get_nom_domaine(self):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    ''' Arrete le traitement des messages pour le domaine '''
    def arreter_traitement_messages(self):
        self._arret_en_cours = True
        self._stop_event.set()
        if self.channel_mq is not None:
            self.channel_mq.close()

    def demarrer_processus(self, processus, parametres):
        self.demarreur_processus.demarrer_processus(processus, parametres)

    def initialiser_document(self, mg_libelle, doc_defaut):
        """
        Insere un document de configuration du domaine, au besoin. Le libelle doit etre unique dans la collection.
        :param mg_libelle: Libelle a donner au document
        :param doc_defaut: Document a inserer.
        :return:
        """
        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.get_collection()

        # Trouver le document de configuration
        document_configuration = collection_domaine.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: mg_libelle}
        )
        if document_configuration is None:
            self._logger.info("On insere le document %s pour domaine Principale" % mg_libelle)

            # Preparation document de configuration pour le domaine
            configuration_initiale = doc_defaut.copy()
            maintenant = datetime.datetime.utcnow()
            configuration_initiale[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = maintenant
            configuration_initiale[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant

            collection_domaine.insert(configuration_initiale)
        else:
            self._logger.info("Document de %s pour %s: %s" % (
                mg_libelle, str(document_configuration), self.__class__.__name__
            ))

    '''
    Implementer cette methode pour retourner le nom de la queue.
    
    :returns: Nom de la Q a ecouter.
    '''
    def get_nom_queue(self):
        raise NotImplementedError("Methode non-implementee")

    def get_nom_queue_requetes_noeuds(self):
        """
        Optionnel, le nom de la Q pour les requetes de noeuds.
        :return: str Nom de la Q a utiliser
        """
        return None

    def get_nom_queue_requetes_inter(self):
        """
        Optionnel, le nom de la Q pour les requetes inter millegrilles.
        :return: str Nom de la Q a utiliser
        """
        return None

    def get_nom_collection(self):
        raise NotImplementedError("Methode non-implementee")

    def get_collection(self):
        return self.document_dao.get_collection(self.get_nom_collection())

    def arreter(self):
        self._logger.warning("Arret de GestionnaireDomaine")
        self.arreter_traitement_messages()
        for watcher in self._watchers:
            try:
                watcher.stop()
            except Exception as e:
                self._logger.info("Erreur fermeture watcher: %s" % str(e))

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


class WatcherCollectionMongoThread:
    """
    Ecoute les changements sur une collection MongoDB et transmet les documents complets sur RabbitMQ.
    """

    def __init__(
            self,
            contexte: ContexteRessourcesMilleGrilles,
            stop_event: Event,
            nom_collection_mongo: str,
            routing_key: str
    ):
        """
        :param contexte:
        :param stop_event: Stop event utilise par le gestionnaire.
        :param nom_collection_mongo:
        :param routing_key:
        """
        self.__logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__contexte = contexte
        self.__stop_event = stop_event
        self.__nom_collection_mongo = nom_collection_mongo
        self.__routing_key = routing_key

        self.__collection_mongo = None
        self.__thread = None
        self.__curseur_changements = None

    def start(self):
        self.__logger.info("Demarrage thread watcher:%s vers routing:%s" % (
            self.__nom_collection_mongo, self.__routing_key))
        self.__thread = Thread(name="DocWatcher", target=self.run)
        self.__thread.start()

    def stop(self):
        self.__curseur_changements.close()

    def run(self):
        self.__logger.info("Thread watch: %s" % self.__nom_collection_mongo)

        # Boucler tant que le stop event n'est pas active
        while not self.__stop_event.isSet():
            if self.__curseur_changements is not None:
                try:
                    change_event = self.__curseur_changements.next()
                    self.__logger.debug("Watcher event recu: %s" % str(change_event))
                    full_document = change_event['fullDocument']
                    self.__logger.debug("Watcher document recu: %s" % str(full_document))

                    # Ajuster la routing key pour ajouter information si necessaire.
                    routing_key = self.__routing_key
                    mg_libelle = full_document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
                    if mg_libelle is not None:
                        routing_key = '%s.%s' % (routing_key, mg_libelle)

                    # Transmettre document sur MQ
                    self.__contexte.message_dao.transmettre_message_noeuds(
                        full_document, routing_key, encoding=MongoJSONEncoder)
                except StopIteration:
                    self.__logger.info("Arret watcher dans l'iteration courante")

            else:
                self.__stop_event.wait(5)  # Attendre 5 secondes, throttle
                self.__logger.info("Creer pipeline %s" % self.__nom_collection_mongo)
                self._creer_pipeline()

    def _creer_pipeline(self):
        collection_mongo = self.__contexte.document_dao.get_collection(self.__nom_collection_mongo)

        # Tenter d'activer watch par _id pour les documents
        try:
            option = {'full_document': 'updateLookup', 'max_await_time_ms': 1000}
            pipeline = []
            logging.info("Pipeline watch: %s" % str(pipeline))
            self.__curseur_changements = collection_mongo.watch(pipeline, **option)

        except OperationFailure as opf:
            self.__logger.warning("Erreur activation watch, on fonctionne par timer: %s" % str(opf))
            self.__curseur_changements = None


class TraiteurRequeteDomaineNoeud:
    """
    Execute les requetes faites par les noeuds sur le topic domaine._domaine_.requete.noeud
    """

    def __init__(self):
        pass
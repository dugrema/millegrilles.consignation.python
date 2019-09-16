# Module avec utilitaires generiques pour mgdomaines
from millegrilles import Constantes
from millegrilles.dao.MessageDAO import JSONHelper, BaseCallback
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
        super().set_logging_level()
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            logging.getLogger('mgdomaines').setLevel(logging.DEBUG)
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
        if self.channel_mq is not None:
            # Fermer le vieux channel
            try:
                self.channel_mq.close()
            finally:
                self.channel_mq = None

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


class GestionnaireDomaineStandard(GestionnaireDomaine):
    """
    Implementation des Q standards pour les domaines.
    """

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        nom_millegrille = contexte.configuration.nom_millegrille

        # Queue message handlers
        self.__handler_transaction = None
        self.__handler_cedule = None
        self.__handler_requetes_noeuds = None

        self.generateur = self.contexte.generateur_transactions

    def configurer(self):
        super().configurer()

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        # Index noeud, _mg-libelle
        collection_domaine.create_index([
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])
        collection_domaine.create_index([
            (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1)
        ])
        collection_domaine.create_index([
            (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, -1)
        ])

    def setup_rabbitmq(self, channel):
        nom_queue_transactions = '%s.%s' % (self.get_nom_queue(), 'transactions')
        nom_queue_ceduleur = '%s.%s' % (self.get_nom_queue(), 'ceduleur')
        nom_queue_processus = '%s.%s' % (self.get_nom_queue(), 'processus')
        nom_queue_requetes_noeuds = '%s.%s' % (self.get_nom_queue(), 'requete.noeuds')

        # Configurer la Queue pour les transactions
        def callback_init_transaction(queue, self=self, callback=self.get_handler_transaction().callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_transactions,
                routing_key='destinataire.domaine.%s.#' % self.get_nom_queue(),
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_transactions,
            durable=False,
            callback=callback_init_transaction,
        )

        # Configuration la queue pour le ceduleur
        def callback_init_cedule(queue, self=self, callback=self.get_handler_cedule().callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_ceduleur,
                routing_key='ceduleur.#',
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_ceduleur,
            durable=False,
            callback=callback_init_cedule,
        )

        # Queue pour les processus
        def callback_init_processus(queue, self=self, callback=self.traitement_evenements.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_processus,
                routing_key='processus.domaine.%s.#' % self.get_nom_domaine(),
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_processus,
            durable=False,
            callback=callback_init_processus,
        )

        # Queue pour les requetes de noeuds
        def callback_init_requetes_noeuds(queue, self=self, callback=self.get_handler_requetes_noeuds().callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_noeuds,
                queue=nom_queue_requetes_noeuds,
                routing_key='requete.%s.#' % self.get_nom_domaine(),
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_requetes_noeuds,
            durable=False,
            callback=callback_init_requetes_noeuds,
        )

    def map_transaction_vers_document(self, transaction: dict, document: dict):
        for key, value in transaction.items():
            if key != Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE and not key.startswith('_'):
                document[key] = value

    def get_handler_transaction(self):
        raise NotImplementedError("Pas implemente")

    def get_handler_cedule(self):
        raise NotImplementedError("Pas implemente")

    def get_handler_requetes_noeuds(self):
        raise NotImplementedError("Pas implemente")


class TraitementRequetesNoeuds(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._gestionnaire = gestionnaire
        self._generateur = gestionnaire.contexte.generateur_transactions

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        exchange = method.exchange
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        enveloppe_certificat = self.contexte.verificateur_transaction.verifier(message_dict)

        self._logger.debug("Certificat: %s" % str(enveloppe_certificat))
        resultats = list()
        for requete in message_dict['requetes']:
            resultat = self.executer_requete(requete)
            resultats.append(resultat)

        # Genere message reponse
        self.transmettre_reponse(message_dict, resultats, properties.reply_to, properties.correlation_id)

    def executer_requete(self, requete):
        self._logger.debug("Requete: %s" % str(requete))
        collection = self.contexte.document_dao.get_collection(self._gestionnaire.get_nom_collection())
        filtre = requete.get('filtre')
        projection = requete.get('projection')
        sort_params = requete.get('sort')

        if projection is None:
            curseur = collection.find(filtre)
        else:
            curseur = collection.find(filtre, projection)

        curseur.limit(2500)  # Mettre limite sur nombre de resultats

        if sort_params is not None:
            curseur.sort(sort_params)

        resultats = list()
        for resultat in curseur:
            resultats.append(resultat)

        self._logger.debug("Resultats: %s" % str(resultats))

        return resultats

    def transmettre_reponse(self, requete, resultats, replying_to, correlation_id=None):
        # enveloppe_val = generateur.soumettre_transaction(requete, 'millegrilles.domaines.Principale.creerAlerte')
        if correlation_id is None:
            correlation_id = requete[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        message_resultat = {
            'resultats': resultats,
        }

        self._generateur.transmettre_reponse(message_resultat, replying_to, correlation_id)


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


class RegenerateurDeDocuments:
    """
    Efface et regenere les /documents d'un domaine.
    """

    def __init__(self, gestionnaire_domaine):
        self._gestionnaire_domaine = gestionnaire_domaine

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    @property
    def contexte(self):
        return self._gestionnaire_domaine.contexte

    def regenerer_documents(self):
        """
        Effectue une requete pour chaque type de transaction du domaine, en ordonnant les transactions
        completes et traitees correctement en ordre de traitement dans la MilleGrille avec autorite.

        Le groupe de base est: toutes les transactions traitees, en ordre.
        :return:
        """
        self.supprimer_documents()

        # Grouper et executer les transactions
        generateur_groupes_transactions = self.creer_generateur_transactions()
        for transactions in generateur_groupes_transactions:
            self.traiter_transactions(transactions)

    def supprimer_documents(self):
        """
        Supprime les documents de la collection
        :return:
        """
        nom_collection_documents = self._gestionnaire_domaine.get_nom_collection()
        self.__logger.info("Supprimer les documents de %s" % nom_collection_documents)

        collection_documents = self._gestionnaire_domaine.get_collection()
        collection_documents.delete_many({})

    def traiter_transactions(self, curseur_transactions):
        for transaction in curseur_transactions:
            self.traiter_transaction(transaction)

    def traiter_transaction(self, transaction):
        """
        Traite la transaction pour simuler la reception et sauvegarde initiale
        :param transaction:
        :return:
        """
        self.__logger.debug("Traitement transaction %s" % transaction[Constantes.MONGO_DOC_ID])

    def creer_generateur_transactions(self):
        return GroupeurTransactionsARegenerer(self._gestionnaire_domaine)


class GroupeurTransactionsARegenerer:
    """
    Classe qui permet de grouper les transactions d'un domaine pour regenerer les documents.
    Groupe toutes les transactions dans un seul groupe, en ordre de transaction_traitee.
    """

    def __init__(self, gestionnaire_domaine: GestionnaireDomaine):
        self._gestionnaire_domaine = gestionnaire_domaine
        self._curseur = None
        self._complet = False

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._preparer_curseur_transactions()

    def _preparer_curseur_transactions(self):
        nom_collection_transaction = self._gestionnaire_domaine.get_collection_transaction_nom()
        self.__logger.debug('Preparer curseur transactions sur %s' % nom_collection_transaction)

        collection_transactions = self._gestionnaire_domaine.contexte.document_dao.get_collection(nom_collection_transaction)

        filtre, index = self._preparer_requete()
        self._curseur = collection_transactions.find(filtre, sort=index).hint(index)

    def _preparer_requete(self):
        nom_millegrille = self._gestionnaire_domaine.contexte.configuration.nom_millegrille

        # Parcourir l'index:
        #  - _evenements.transaction_complete
        #  - _evenements.NOM_MILLEGRILLE.transaction_traitee
        index = [
            ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                        Constantes.EVENEMENT_TRANSACTION_COMPLETE), 1),
            ('%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille,
                           Constantes.EVENEMENT_TRANSACTION_TRAITEE), 1)
        ]
        # ordre_tri = index  # L'index est trie dans l'ordre necessaire

        # Filtre par transaction completee:
        #  - _evenements.transaction_complete = True
        #  - _evenements.NOM_MILLEGRILLE.transaction_traitee existe
        filtre = {
            '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                       Constantes.EVENEMENT_TRANSACTION_COMPLETE): True,
            '%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille,
                          Constantes.EVENEMENT_TRANSACTION_TRAITEE): {'$exists': True}
        }

        return filtre, index

    def __iter__(self):
        return self

    def __next__(self):
        """
        Retourne un curseur Mongo avec les transactions a executer en ordre.
        :return:
        """
        if not self._complet:
            self._complet = True  # Ce generateur supporte un seul groupe
            return self._curseur

        raise StopIteration()

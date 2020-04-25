# Module avec utilitaires generiques pour mgdomaines
import logging
import json
import datetime
import lzma
import hashlib
import requests
import pytz

from os import path
from pika.exceptions import ChannelClosed
from pymongo.errors import OperationFailure
from bson import ObjectId
from threading import Thread, Event, Lock
from pathlib import Path
from cryptography.hazmat.primitives import hashes

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup, ConstantesPki, ConstantesDomaines
from millegrilles.dao.MessageDAO import JSONHelper, TraitementMessageDomaine, \
    TraitementMessageDomaineMiddleware, TraitementMessageDomaineRequete, TraitementMessageCedule, TraitementMessageDomaineCommande
from millegrilles.MGProcessus import MGPProcessusDemarreur, MGPProcesseurTraitementEvenements, MGPProcesseurRegeneration, MGProcessus
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.transaction.ConsignateurTransaction import ConsignateurTransactionCallback
from millegrilles.util.JSONMessageEncoders import BackupFormatEncoder, DateFormatEncoder, decoder_backup
from millegrilles.SecuritePKI import HachageInvalide, CertificatInvalide


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
        self.__channel = None  # Ouvrir un channel pour savoir quand MQ est pret
        self.__wait_mq_ready = Event()

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        """ L'initialisation connecte RabbitMQ, MongoDB, lance la configuration """
        super().initialiser(init_document, init_message, connecter)
        self.initialiser_2()

    def initialiser_2(self, contexte=None):
        if contexte is not None:
            self._contexte = contexte

        self.contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        super().on_channel_open(channel)
        channel.basic_qos(prefetch_count=10)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel

        # MQ est pret, on charge les domaines
        self.__wait_mq_ready.set()

    def on_channel_close(self, channel=None, code=None, reason=None):
        self.__wait_mq_ready.clear()
        self.__channel = None

        if not self._stop_event.is_set():
            try:
                self.contexte.message_dao.enter_error_state()
            except Exception:
                self._logger.exception(
                    "Erreur d'activation mode erreur pour connexion MQ, contoleur gestionnaire va se fermer"
                )
                self.arreter()

        self._logger.info("MQ Channel ferme")

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
        self.__wait_mq_ready.wait(60)
        if not self.__wait_mq_ready.is_set():
            raise Exception("MQ n'est pas pret apres 60 secondes")

        self.charger_domaines()

        if len(self._gestionnaires) > 0:
            self.demarrer_execution_domaines()
        else:
            self._stop_event.set()
            self._logger.fatal("Aucun gestionnaire de domaine n'a ete charge. Execution interrompue.")

        # Surveiller les gestionnaires - si un gestionnaire termine son execution, on doit tout fermer
        try:
            while not self._stop_event.is_set():
                # self.contexte.message_dao.start_consuming()  # Blocking
                # self._logger.debug("Erreur consuming, attendre 5 secondes pour ressayer")

                # Verifier que tous les domaines sont actifs et fonctionnels
                for gestionnaire in self._gestionnaires:
                    gestionnaire.executer_entretien()
                    if not gestionnaire.is_ok:
                        self._logger.error("Gestionnaire domaine %s est en erreur/termine, on arrete le controleur" % gestionnaire.__class__.__name__)
                        self.arreter()

                self._stop_event.wait(15)   # Boucler pour maintenance
        except Exception:
            self._logger.exception("Erreur execution controleur de gestionnaires, arret force")
        finally:
            self.arreter()

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
        self.__contexte = contexte
        self.demarreur_processus = None
        self.json_helper = JSONHelper()
        self._logger = logging.getLogger("%s.GestionnaireDomaine" % __name__)
        self._watchers = list()
        self.channel_mq = None
        self._arret_en_cours = False
        self._stop_event = Event()
        self._traitement_evenements = None
        self.wait_Q_ready = Event()  # Utilise pour attendre configuration complete des Q
        self.wait_Q_ready_lock = Lock()
        self.nb_routes_a_config = 0
        self.__Q_wait_broken = None  # Mis utc a date si on a un timeout pour l'attente de __wait_mq_ready

        self._consumer_tags_parQ = dict()

        # ''' L'initialisation connecte RabbitMQ, MongoDB, lance la configuration '''
    # def initialiser(self):
    #     self.connecter()  # On doit se connecter immediatement pour permettre l'appel a configurer()

    def configurer(self):
        self._traitement_evenements = MGPProcesseurTraitementEvenements(self._contexte, self._stop_event, gestionnaire_domaine=self)
        self._traitement_evenements.initialiser([self.get_collection_processus_nom()])
        """ Configure les comptes, queues/bindings (RabbitMQ), bases de donnees (MongoDB), etc. """
        self.demarreur_processus = MGPProcessusDemarreur(
            self._contexte, self.get_nom_domaine(), self.get_collection_transaction_nom(),
            self.get_collection_processus_nom(), self._traitement_evenements, gestionnaire=self)

    def demarrer(self):
        """ Demarrer une thread pour ce gestionnaire """
        self._logger.debug("Debut thread gestionnaire %s" % self.__class__.__name__)
        # self.configurer()  # Deja fait durant l'initialisation
        self._logger.info("On enregistre la queue %s" % self.get_nom_queue())

        self._contexte.message_dao.register_channel_listener(self)
        self._logger.info("Attente Q et routes prets")
        self.wait_Q_ready.wait(30)  # Donner 30 seconde a MQ

        if not self.wait_Q_ready.is_set():
            self.__Q_wait_broken = datetime.datetime.utcnow()
            if self.nb_routes_a_config > 0:
                self._logger.error("Les routes de Q du domaine ne sont pas configures correctement, il reste %d a configurer" % self.nb_routes_a_config)
            else:
                self._logger.warning('wait_Q_read pas set, on va forcer error state sur la connexion pour recuperer')
            self.message_dao.enter_error_state()
        else:
            self._logger.info("Q et routes prets")

            # Verifier si on doit upgrader les documents avant de commencer a ecouter
            doit_regenerer = self.verifier_version_transactions(self.version_domaine)

            if doit_regenerer:
                self.regenerer_documents()
                self.changer_version_collection(self.version_domaine)

            # Lance le processus de regeneration des rapports sur cedule pour s'assurer d'avoir les donnees a jour
            self.regenerer_rapports_sur_cedule()

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

        self.setup_rabbitmq()  # Setup Q et consumers

    def get_queue_configuration(self):
        """
        :return: Liste de Q avec configuration pour le domaine
        """
        raise NotImplementedError("Pas implemente")

    def setup_rabbitmq(self, consume=True):
        """
        Callback pour faire le setup de rabbitMQ quand le channel est ouvert. Permet aussi de refaire les binding
        avec les Q apres avoir appele unbind_rabbitmq.
        """
        channel = self.channel_mq
        queues_config = self.get_queue_configuration()

        self.nb_routes_a_config = len([r for r in [q.get('routing') for q in queues_config]])
        self.wait_Q_ready.clear()  # Reset flag au besoin
        # channel = self.message_dao.channel
        for queue_config in queues_config:

            def callback_init_transaction(queue, gestionnaire=self, in_queue_config=queue_config, in_consume=consume):
                if in_consume:
                    gestionnaire.inscrire_basicconsume(queue, in_queue_config['callback'])

                routing_list = in_queue_config.get('routing')
                if routing_list is not None:
                    for routing in routing_list:
                        channel.queue_bind(
                            exchange=in_queue_config['exchange'],
                            queue=in_queue_config['nom'],
                            routing_key=routing,
                            callback=self.__compter_route
                        )

            args = {}
            if queue_config.get('arguments'):
                args.update(queue_config.get('arguments'))
            if queue_config.get('ttl'):
                args['x-message-ttl'] = queue_config['ttl']

            durable = False
            if queue_config.get('durable'):
                durable = True

            self._logger.info("Declarer Q %s" % queue_config['nom'])
            channel.queue_declare(
                queue=queue_config['nom'],
                durable=durable,
                callback=callback_init_transaction,
                arguments=args,
            )

    def __compter_route(self, arg1):
        """
        Sert a compter les routes qui sont pretes. Declenche Event wait_Q_ready lorsque complet.
        :param arg1:
        :return:
        """
        # Indiquer qu'une route a ete configuree
        with self.wait_Q_ready_lock:
            self.nb_routes_a_config = self.nb_routes_a_config - 1

            if self.nb_routes_a_config <= 0:
                # Il ne reste plus de routes a configurer, set flag comme pret
                self.wait_Q_ready.set()
                self.__Q_wait_broken = None

    def stop_consuming(self, queue=None):
        """
        Deconnecte les consommateur queues du domaine pour effectuer du travail offline.
        """
        channel = self.channel_mq
        if queue is None:
            tags = channel.consumer_tags
            for tag in tags:
                self._logger.debug("Removing ctag %s" % tag)
                with self.message_dao.lock_transmettre_message:
                    channel.basic_cancel(consumer_tag=tag, nowait=True)
        else:
            ctag = self._consumer_tags_parQ.get(queue)
            if ctag is not None:
                with self.message_dao.lock_transmettre_message:
                    channel.basic_cancel(consumer_tag=ctag, nowait=True)

    def resoumettre_transactions(self):
        """
        Soumets a nouveau les notifications de transactions non completees du domaine.
        Utilise l'ordre de persistance.
        :return:
        """
        idmg = self.configuration.idmg
        champ_complete = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE)
        champ_persiste = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_DOCUMENT_PERSISTE)
        filtre = {
            champ_complete: False
        }
        hint = [
            (champ_complete, 1),
            (champ_persiste, 1)
        ]

        collection_transactions = self.document_dao.get_collection(self.get_collection_transaction_nom())
        transactions_incompletes = collection_transactions.find(filtre, sort=hint).hint(hint)

        try:
            for transaction in transactions_incompletes:
                self._logger.debug("Transaction incomplete: %s" % transaction)
                id_document = transaction[Constantes.MONGO_DOC_ID]
                en_tete = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
                uuid_transaction = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                domaine = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
                self.message_dao.transmettre_evenement_persistance(
                    id_document, uuid_transaction, domaine, None)
        except OperationFailure as of:
            self._logger.error("Collection %s, erreur requete avec hint: %s.\n%s" % (
                self.get_collection_transaction_nom(), str(hint), str(of)))

    def on_channel_close(self, channel=None, code=None, reason=None):
        """
        Callback pour la fermeture du channel
        :param channel:
        :return:
        """
        self._logger.info("Channel ferme: %s, %s" %(code, reason))
        self.channel_mq = None

    def inscrire_basicconsume(self, queue, callback):
        """
        Inscrit le channel sur la queue.
        :param queue:
        :param callback:
        :return: Consumer tag (ctag)
        """
        if isinstance(queue, str):
            nom_queue = queue
        else:
            nom_queue = queue.method.queue

        self._logger.info("Queue prete, on enregistre basic_consume %s" % nom_queue)
        with self.message_dao.lock_transmettre_message:
            ctag = self.channel_mq.basic_consume(callback, queue=nom_queue, no_ack=False)

        # Conserver le ctag - permet de faire cancel au besoin (e.g. long running process)
        self._consumer_tags_parQ[nom_queue] = ctag

        return ctag

    def demarrer_watcher_collection(self, nom_collection_mongo: str, routing_key: str, exchange_router=None):
        """
        Enregistre un watcher et demarre une thread qui lit le pipeline dans MongoDB. Les documents sont
        lus au complet et envoye avec la routing_key specifiee.
        :param nom_collection_mongo: Nom de la collection dans MongoDB pour cette MilleGrille
        :param routing_key: Nom du topic a enregistrer,
               e.g. noeuds.source.millegrilles_domaines_SenseursPassifs.affichage.__nom_noeud__.__no_senseur__
        :param exchange_router: Routeur pour determiner sur quels exchanges le document sera place.
        :return:
        """
        watcher = WatcherCollectionMongoThread(self._contexte, self._stop_event, nom_collection_mongo, routing_key, exchange_router)
        self._watchers.append(watcher)
        watcher.start()

    def identifier_processus(self, domaine_transaction):
        nom_domaine = self.get_nom_domaine()
        operation = domaine_transaction.replace('%s.' % nom_domaine, '')

        if operation == Constantes.TRANSACTION_ROUTING_DOCINITIAL:
            processus = "%s:millegrilles_MGProcessus:MGProcessusDocInitial" % operation
        elif operation == Constantes.TRANSACTION_ROUTING_UPDATE_DOC:
            processus = "%s:millegrilles_MGProcessus:MGProcessusUpdateDoc" % operation
        else:
            raise TransactionTypeInconnuError("Type de transaction inconnue: routing: %s" % domaine_transaction)

        return processus

    def regenerer_rapports_sur_cedule(self):
        """ Permet de regenerer les documents de rapports sur cedule lors du demarrage du domaine """
        pass

    def regenerer_documents(self, stop_consuming=True):
        self._logger.info("Regeneration des documents de %s" % self.get_nom_domaine())

        # Desactiver temporairement toutes les threads de watchers
        try:
            for watcher in self._watchers:
                watcher.stop()

            processeur_regeneration = MGPProcesseurRegeneration(self.__contexte, self)
            processeur_regeneration.regenerer_documents(stop_consuming=stop_consuming)
        finally:
            # Reactiver les watchers
            for watcher in self._watchers:
                watcher.start()

        self._logger.info("Fin regeneration des documents de %s" % self.get_nom_domaine())

        return {'complet': True}

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
        self._traitement_evenements.arreter()

    def demarrer_processus(self, processus, parametres):
        self.demarreur_processus.demarrer_processus(processus, parametres)

    def verifier_version_transactions(self, version_domaine):
        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.get_collection()

        # Trouver le document de configuration
        document_configuration = collection_domaine.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.LIBVAL_CONFIGURATION}
        )
        self._logger.debug("Document config domaine: %s" % document_configuration)

        doit_regenerer = True
        if document_configuration is not None:
            version_collection = document_configuration.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION)
            if version_collection is None:
                self._logger.warning(
                    "La collection a une version inconnue a celle du code Python (V%d), on regenere les documents" %
                    version_domaine
                )
            elif version_collection == version_domaine:
                doit_regenerer = False
            elif version_collection > version_domaine:
                message_erreur = "Le code du domaine est V%d, le document de configuration est V%d (plus recent)" % (
                    version_domaine, version_collection
                )
                raise Exception(message_erreur)
            else:
                self._logger.warning(
                    "La collection a une version inferieure (V%d) a celle du code Python (V%d), on regenere les documents" %
                    (version_collection, version_domaine)
                )

        return doit_regenerer

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
            # maintenant = datetime.datetime.utcnow()
            # configuration_initiale[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = maintenant.timestamp()
            # configuration_initiale[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant.timestamp()
            nouveau_doc = {
                Constantes.DOCUMENT_INFODOC_SOUSDOCUMENT: configuration_initiale
            }

            # collection_domaine.insert(configuration_initiale)
            domaine_transaction = '%s.%s' % (self.get_nom_domaine(), Constantes.TRANSACTION_ROUTING_DOCINITIAL)
            self.generateur_transactions.soumettre_transaction(nouveau_doc, domaine_transaction)
        else:
            self._logger.debug("Document de %s pour %s: %s" % (
                mg_libelle, str(document_configuration), self.__class__.__name__
            ))

    def changer_version_collection(self, version):
        nouveau_doc = {
            Constantes.DOCUMENT_INFODOC_SOUSDOCUMENT: {
                Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.LIBVAL_CONFIGURATION,
                Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION: version
            }
        }

        # collection_domaine.insert(configuration_initiale)
        domaine_transaction = '%s.%s' % (self.get_nom_domaine(), Constantes.TRANSACTION_ROUTING_UPDATE_DOC)
        self.generateur_transactions.soumettre_transaction(nouveau_doc, domaine_transaction)

    def marquer_transaction_en_erreur(self, dict_message):
        # Type de transaction inconnue, on lance une exception
        id_transaction = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO]
        domaine = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        collection = ConsignateurTransactionCallback.identifier_collection_domaine(domaine)

        evenement = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.MONGO_DOC_ID: id_transaction,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: collection,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT,
        }
        self.message_dao.transmettre_message(evenement, Constantes.TRANSACTION_ROUTING_EVENEMENT)

    '''
    Implementer cette methode pour retourner le nom de la queue.

    :returns: Nom de la Q a ecouter.
    '''
    def get_nom_queue(self):
        raise NotImplementedError("Methode non-implementee")

    def get_nom_collection(self):
        raise NotImplementedError("Methode non-implementee")

    def get_collection(self):
        return self.document_dao.get_collection(self.get_nom_collection())

    def get_transaction(self, id_transaction):
        collection_transactions = self.document_dao.get_collection(self.get_collection_transaction_nom())
        return collection_transactions.find_one({Constantes.MONGO_DOC_ID: ObjectId(id_transaction)})

    def get_transaction_par_token_resumer(self, token_resumer):
        collection_transactions = self.document_dao.get_collection(self.get_collection_transaction_nom())
        libelle_token = '%s.%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            Constantes.EVENEMENT_RESUMER,
            Constantes.EVENEMENT_MESSAGE_TOKEN
        )
        return collection_transactions.find_one({libelle_token: token_resumer})

    def arreter(self):
        self._logger.warning("Arret de GestionnaireDomaine")
        self.arreter_traitement_messages()
        self._stop_event.set()
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
    def generateur_transactions(self):
        return self._contexte.generateur_transactions

    @property
    def verificateur_transaction(self):
        return self._contexte.verificateur_transaction

    @property
    def verificateur_certificats(self):
        return self._contexte.verificateur_certificats

    def creer_regenerateur_documents(self):
        return RegenerateurDeDocuments(self)

    @property
    def _contexte(self):
        return self.__contexte

    @property
    def version_domaine(self):
        return Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6

    def executer_entretien(self):
        pass

    @property
    def is_ok(self):
        """
        :return: False si le gestionnaire ne fonctionne pas bien et requiert un redemarrage complet
        """
        if not self._stop_event.is_set() and not self.wait_Q_ready.is_set():
            # Verifier si on est en train de charger le domaine ou si quelque chose a empeche le deploiement
            if not self.__Q_wait_broken:
                return True
            else:
                # On donne 2 minutes pour tenter de recuperer / se reconnecter a MQ
                return datetime.datetime.utcnow() > self.__Q_wait_broken + datetime.timedelta(minutes=2)
        else:
            return not self._stop_event.is_set()


class TraitementCommandesSecures(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key

        nom_domaine = self.gestionnaire.get_collection_transaction_nom()

        if routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_horaire(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_QUOTIDIEN.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_quotidien(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_MENSUEL.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_mensuel(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_ANNUEL.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_annuel(message_dict)
        else:
            raise ValueError("Commande inconnue: " + routing_key)

        return resultat


class TraitementCommandesProtegees(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict) -> dict:
        routing_key = method.routing_key

        commande = method.routing_key.split('.')[-1]
        nom_domaine = self.gestionnaire.get_collection_transaction_nom()

        if routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE_GLOBAL:
            resultat = self.gestionnaire.declencher_backup_horaire(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_RESET_GLOBAL:
            resultat = self.gestionnaire.reset_backup(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_horaire(message_dict)
        elif routing_key == ConstantesDomaines.COMMANDE_GLOBAL_REGENERER:
            resultat = self.gestionnaire.regenerer_documents()
        elif commande == ConstantesDomaines.COMMANDE_REGENERER:
            resultat = self.gestionnaire.regenerer_documents()
        else:
            raise ValueError("Commande inconnue: " + routing_key)

        return resultat


class GestionnaireDomaineStandard(GestionnaireDomaine):
    """
    Implementation des Q standards pour les domaines.
    """

    def __init__(self, contexte):
        super().__init__(contexte)

        self.__traitement_middleware = TraitementMessageDomaineMiddleware(self)
        self.__traitement_noeud = TraitementMessageDomaineRequete(self)
        self.__handler_backup = HandlerBackupDomaine(
            contexte, self.get_nom_domaine(), self.get_collection_transaction_nom(), self.get_collection())

        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_commandes = {
            Constantes.SECURITE_SECURE: TraitementCommandesSecures(self),
            Constantes.SECURITE_PROTEGE: TraitementCommandesProtegees(self),
        }

        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def configurer(self):
        super().configurer()

        self._logger.debug("Type gestionnaire : " + self.__class__.__name__)

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        # Index noeud, _mg-libelle
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='mglibelle'
        )
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1)
            ],
            name='datecreation'
        )
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, -1)
            ],
            name='dernieremodification'
        )

    def get_queue_configuration(self):
        """
        :return: Liste de configuration pour les Q du domaine
        """

        queues_config = [
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'transactions'),
                'routing': [
                    'destinataire.domaine.%s.#' % self.get_nom_domaine(),
                ],
                'exchange': self.configuration.exchange_middleware,
                'ttl': 300000,
                'callback': self.get_handler_transaction().callbackAvecAck
            },
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'ceduleur'),
                'routing': [
                    'ceduleur.#',
                ],
                'exchange': self.configuration.exchange_middleware,
                'ttl': 30000,
                'callback': self.get_handler_cedule().callbackAvecAck
            },
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'processus'),
                'routing': [
                    'processus.domaine.%s.#' % self.get_nom_domaine()
                ],
                'exchange': self.configuration.exchange_middleware,
                'ttl': 600000,
                'callback': self._traitement_evenements.callbackAvecAck
            }
        ]

        # Ajouter les handles de requete par niveau de securite
        for securite, handler_requete in self.get_handler_requetes().items():
            if securite == Constantes.SECURITE_SECURE:
                exchange = self.configuration.exchange_middleware
            elif securite == Constantes.SECURITE_PROTEGE:
                exchange = self.configuration.exchange_noeuds
            elif securite == Constantes.SECURITE_PRIVE:
                exchange = self.configuration.exchange_prive
            else:
                exchange = self.configuration.exchange_public

            queues_config.append({
                'nom': '%s.%s' % (self.get_nom_queue(), 'requete.noeuds.' + securite),
                'routing': [
                    'requete.%s.#' % self.get_nom_domaine(),
                ],
                'exchange': exchange,
                'ttl': 20000,
                'callback': handler_requete.callbackAvecAck
            })

        for securite, handler_requete in self.get_handler_commandes().items():
            if securite == Constantes.SECURITE_SECURE:
                exchange = self.configuration.exchange_middleware
            elif securite == Constantes.SECURITE_PROTEGE:
                exchange = self.configuration.exchange_noeuds
            elif securite == Constantes.SECURITE_PRIVE:
                exchange = self.configuration.exchange_prive
            else:
                exchange = self.configuration.exchange_public

            queues_config.append({
                'nom': '%s.%s' % (self.get_nom_queue(), 'commande.' + securite),
                'routing': [
                    'commande.%s.#' % self.get_nom_domaine(),
                    'commande.global.#',
                ],
                'exchange': exchange,
                'ttl': 20000,
                'callback': handler_requete.callbackAvecAck
            })

        return queues_config

    def map_transaction_vers_document(self, transaction: dict, document: dict):
        for key, value in transaction.items():
            if key != Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE and not key.startswith('_'):
                document[key] = value

    def get_handler_transaction(self):
        return self.__traitement_middleware

    def get_handler_requetes_noeuds(self):
        return self.__traitement_noeud

    def get_handler_requetes(self) -> dict:
        return {
            Constantes.SECURITE_PROTEGE: self.get_handler_requetes_noeuds()
        }

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def get_handler_cedule(self):
        return self.__handler_cedule

    def traiter_cedule(self, evenement):
        """ Appele par __handler_cedule lors de la reception d'un message sur la Q .ceduleur du domaine """

        indicateurs = evenement['indicateurs']
        self._logger.debug("Cedule webPoll: %s" % str(indicateurs))

        # Faire la liste des cedules a declencher
        if 'heure' in indicateurs:
            self.nettoyer_processus()
            self.transmettre_commande_backup_horaire()

    def transmettre_commande_backup_horaire(self):
        """
        Transmet une commande pour faire un backup horaire pour ce domaine.

        :return:
        """
        commande_backup = {
            ConstantesBackup.LIBELLE_HEURE: datetime.datetime.utcnow() - datetime.timedelta(hours=1),
            ConstantesBackup.LIBELLE_DOMAINE: self.get_nom_domaine(),
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace(
                '_DOMAINE_', self.get_nom_domaine()),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
        )

    def nettoyer_processus(self):
        collection_processus = self.document_dao.get_collection(self.get_collection_processus_nom())

        date_complet = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        date_incomplet = datetime.datetime.utcnow() - datetime.timedelta(days=14)

        filtre_complet = {
            "etape-suivante": {"$exists": False},
            "_mg-derniere-modification": {"$lte": date_complet}
        }
        filtre_incomplet = {
            "etape-suivante": {"$exists": True},
            "_mg-creation": {"$lte": date_incomplet}
        }

        collection_processus.delete_many(filtre_complet)
        collection_processus.delete_many(filtre_incomplet)

    def declencher_backup_horaire(self, declencheur: dict):
        """
        Declenche un backup horaire. Maximum qui peut etre demande est est l'heure precedente.

        :param declencheur:
        :return:
        """
        # Verifier qu'on ne demande pas un backup de l'heure courante
        maintenant = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        heure_precedente = datetime.datetime(year=maintenant.year, month=maintenant.month, day=maintenant.day, hour=maintenant.hour)

        try:
            heure = datetime.datetime.fromtimestamp(declencheur[ConstantesBackup.LIBELLE_HEURE], tz=datetime.timezone.utc)
            heure_demandee = datetime.datetime(year=heure.year, month=heure.month, day=heure.day, hour=heure.hour)

            if heure_demandee > heure_precedente:
                # Reculer d'une heure
                heure_demandee = heure_precedente
        except KeyError:
            heure_demandee = heure_precedente

        domaine = self.get_nom_domaine()
        securite = declencheur[ConstantesBackup.LIBELLE_SECURITE]

        self._logger.info("Declencher backup horaire pour domaine %s, securite %s, heure %s" % (domaine, securite, str(heure_demandee)))
        routing = domaine
        nom_module = 'millegrilles_Domaines'
        nom_classe = 'BackupHoraire'
        processus = "%s:%s:%s" % (routing, nom_module, nom_classe)

        parametres = {
            'heure': heure_demandee,
            'securite': securite,
        }

        self.demarrer_processus(processus, parametres)

    def reset_backup(self, message_dict):
        self._logger.debug("Reset backup transactions pour domaine " + self.get_nom_domaine())

        unset_champs = list()
        for champ in [
            Constantes.EVENEMENT_TRANSACTION_BACKUP_RESTAURE,
            Constantes.EVENEMENT_TRANSACTION_BACKUP_HORAIRE_COMPLETE,
            Constantes.EVENEMENT_TRANSACTION_BACKUP_ERREUR]:

            unset_champs.append('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, champ))

        champs = {
            '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG): False,
        }

        evenement = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: self.get_nom_domaine(),
            Constantes.EVENEMENT_MESSAGE_UNSET: unset_champs,
            Constantes.EVENEMENT_MESSAGE_EVENEMENTS: champs,
        }
        self._contexte.message_dao.transmettre_message(evenement, Constantes.TRANSACTION_ROUTING_EVENEMENTRESET)

    def executer_backup_horaire(self, declencheur: dict):
        heure = datetime.datetime.fromtimestamp(declencheur[ConstantesBackup.LIBELLE_HEURE], tz=datetime.timezone.utc)
        domaine = declencheur[ConstantesBackup.LIBELLE_DOMAINE]
        securite = declencheur[ConstantesBackup.LIBELLE_SECURITE]
        backup_precedent = declencheur.get(ConstantesBackup.LIBELLE_BACKUP_PRECEDENT)
        self._logger.info("Declencher backup horaire pour domaine %s, securite %s, heure %s" % (domaine, securite, str(heure)))
        self.handler_backup.backup_domaine(heure, domaine)

    def declencher_backup_quotidien(self, declencheur: dict):
        jour = datetime.datetime.fromtimestamp(declencheur[ConstantesBackup.LIBELLE_JOUR], tz=datetime.timezone.utc)
        domaine = declencheur[ConstantesBackup.LIBELLE_DOMAINE]
        securite = declencheur[ConstantesBackup.LIBELLE_SECURITE]
        self._logger.info("Declencher backup quotidien pour domaine %s, securite %s, jour %s" % (domaine, securite, str(jour)))
        self.handler_backup.creer_backup_quoditien(self.get_nom_domaine(), jour)

    def declencher_backup_mensuel(self, declencheur: dict):
        mois = datetime.datetime.fromtimestamp(declencheur[ConstantesBackup.LIBELLE_MOIS], tz=datetime.timezone.utc)
        domaine = declencheur[ConstantesBackup.LIBELLE_DOMAINE]
        securite = declencheur[ConstantesBackup.LIBELLE_SECURITE]
        self._logger.info("Declencher backup mensuel pour domaine %s, securite %s, mois %s" % (domaine, securite, str(mois)))
        self.__handler_backup.creer_backup_mensuel(self.get_nom_domaine(), mois)

    def declencher_backup_annuel(self, declencheur: dict):
        annee = datetime.datetime.fromtimestamp(declencheur[ConstantesBackup.LIBELLE_ANNEE], tz=datetime.timezone.utc)
        domaine = declencheur[ConstantesBackup.LIBELLE_DOMAINE]
        securite = declencheur[ConstantesBackup.LIBELLE_SECURITE]
        self._logger.info("Declencher backup annuel pour domaine %s, securite %s, annee %s" % (domaine, securite, str(annee)))
        self.__handler_backup.creer_backup_annuel(self.get_nom_domaine(), annee)

    @property
    def handler_backup(self):
        return self.__handler_backup


class TraitementRequetesNoeuds(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        exchange = method.exchange
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        enveloppe_certificat = self.gestionnaire.verificateur_transaction.verifier(message_dict)

        self._logger.debug("Certificat: %s" % str(enveloppe_certificat))
        resultats = list()
        for requete in message_dict['requetes']:
            resultat = self.executer_requete(requete)
            resultats.append(resultat)

        # Genere message reponse
        self.transmettre_reponse(message_dict, resultats, properties.reply_to, properties.correlation_id)

    def executer_requete(self, requete):
        self._logger.debug("Requete: %s" % str(requete))
        collection = self.document_dao.get_collection(self._gestionnaire.get_nom_collection())
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

        self.gestionnaire.generateur_transactions.transmettre_reponse(message_resultat, replying_to, correlation_id)


class ExchangeRouter:
    """
    Classe qui permet de determiner sur quel echange le document doit etre soumis
    """

    def __init__(self, contexte: ContexteRessourcesMilleGrilles):
        self.__contexte = contexte

        self._exchange_public = self.__contexte.configuration.exchange_public
        self._exchange_prive = self.__contexte.configuration.exchange_prive
        self._exchange_protege = self.__contexte.configuration.exchange_noeuds
        self._exchange_secure = self.__contexte.configuration.exchange_middleware

    def determiner_exchanges(self, document: dict) -> list:
        """
        :return: Liste des echanges sur lesquels le document doit etre soumis
        """
        return [self._exchange_protege]


class WatcherCollectionMongoThread:
    """
    Ecoute les changements sur une collection MongoDB et transmet les documents complets sur RabbitMQ.
    """

    def __init__(
            self,
            contexte: ContexteRessourcesDocumentsMilleGrilles,
            stop_event: Event,
            nom_collection_mongo: str,
            routing_key: str,
            exchange_router: ExchangeRouter,
    ):
        """
        :param contexte:
        :param stop_event: Stop event utilise par le gestionnaire.
        :param nom_collection_mongo:
        :param routing_key:
        :param exchange_router: Permet de determiner quels documents vont sur les echanges proteges, prives et publics.
        """
        self.__logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__contexte = contexte
        self.__stop_event = stop_event
        self.__nom_collection_mongo = nom_collection_mongo
        self.__routing_key = routing_key

        self.__exchange_router = exchange_router
        if self.__exchange_router is None:
            self.__exchange_router = ExchangeRouter(contexte)

        self.__collection_mongo = None
        self.__thread = None
        self.__curseur_changements = None

    def start(self):
        self.__logger.info("Demarrage thread watcher:%s vers routing:%s" % (
            self.__nom_collection_mongo, self.__routing_key))
        self.__thread = Thread(name="DocWatcher", target=self.run, daemon=True)
        self.__thread.start()

    def stop(self):
        try:
            self.__curseur_changements.close()
        except AttributeError:
            pass

    def run(self):
        self.__logger.info("Thread watch: %s" % self.__nom_collection_mongo)

        # Boucler tant que le stop event n'est pas active
        while not self.__stop_event.isSet():
            if self.__curseur_changements is not None:
                try:
                    change_event = self.__curseur_changements.next()
                    self.__logger.debug("Watcher event recu: %s" % str(change_event))

                    operation_type = change_event['operationType']
                    if operation_type in ['insert', 'update', 'replace']:
                        full_document = change_event['fullDocument']
                        self._emettre_document(full_document)
                    elif operation_type == 'invalidate':
                        # Curseur ferme
                        self.__logger.warning("Curseur watch a ete invalide, on le ferme.\n%s" % str(change_event))
                        self.__curseur_changements = None
                    elif operation_type in ['delete', 'drop', 'rename']:
                        pass
                    elif operation_type == 'dropDatabase':
                        self.__logger.error("Drop database event : %s" % str(change_event))
                    else:
                        self.__logger.debug("Evenement non supporte: %s" % operation_type)
                        self.__stop_event.wait(0.5)  # Attendre 0.5 secondes, throttle
                except StopIteration:
                    self.__logger.info("Arret watcher dans l'iteration courante")
                    self.__curseur_changements = None
                except Exception:
                    self.__logger.exception("Erreur dans le traitement du watcher")
                    self.__stop_event.wait(1)  # Attendre 1 seconde, throttle

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

    def _emettre_document(self, document):
        self.__logger.debug("Watcher document recu: %s" % str(document))

        # Ajuster la routing key pour ajouter information si necessaire.
        routing_key = self.__routing_key
        exchanges = self.__exchange_router.determiner_exchanges(document)
        mg_libelle = document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
        if mg_libelle is not None:
            routing_key = '%s.%s' % (routing_key, mg_libelle)

        # Transmettre document sur MQ
        self.__contexte.generateur_transactions.emettre_message(document, routing_key, exchanges)


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

        self._transactions_resumer = dict()  # Transactions a resumer

    @property
    def contexte(self):
        return self._gestionnaire_domaine.contexte

    def ajouter_transaction_resumer(self, token, transaction):
        self._transactions_resumer[token] = transaction

    def consommer_transaction_resumer(self, token_resumer: str):
        """
        Retourner une transaction qui correspond au token. Supprime la reference.

        :param token_resumer:
        :return:
        """
        transaction = self._transactions_resumer.get(token_resumer)
        if transaction:
            del self._transactions_resumer[token_resumer]

        return transaction

    def supprimer_documents(self):
        """
        Supprime les documents de la collection
        :return:
        """
        nom_collection_documents = self._gestionnaire_domaine.get_nom_collection()
        self.__logger.info("Supprimer les documents de %s" % nom_collection_documents)

        collection_documents = self._gestionnaire_domaine.get_collection()
        collection_documents.delete_many({})

    def creer_generateur_transactions(self):
        return GroupeurTransactionsARegenerer(self._gestionnaire_domaine)


class RegenerateurDeDocumentsSansEffet(RegenerateurDeDocuments):
    """
    Empeche la regeneration d'un domaine
    """

    def supprimer_documents(self):
        pass

    def creer_generateur_transactions(self):
        return GroupeurTransactionsSansEffet()


class GroupeurTransactionsARegenerer:
    """
    Classe qui permet de grouper les transactions d'un domaine pour regenerer les documents.
    Groupe toutes les transactions dans un seul groupe, en ordre de transaction_traitee.
    """

    def __init__(self, gestionnaire_domaine: GestionnaireDomaine, transactions_a_ignorer: list = None):
        """

        :param gestionnaire_domaine:
        :param transaction_a_ignorer: Liste de transactions a ingorer pour regenerer ce domaine.
        """
        self.__gestionnaire_domaine = gestionnaire_domaine
        self.__transactions_a_ignorer = transactions_a_ignorer
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.__complet = False

    def __preparer_curseur_transactions(self):
        nom_collection_transaction = self.__gestionnaire_domaine.get_collection_transaction_nom()
        self.__logger.debug('Preparer curseur transactions sur %s' % nom_collection_transaction)

        collection_transactions = self.__gestionnaire_domaine.document_dao.get_collection(nom_collection_transaction)

        filtre, index = self.__preparer_requete()
        return collection_transactions.find(filtre).sort(index).hint(index)

    def __preparer_requete(self):
        idmg = self.__gestionnaire_domaine.configuration.idmg

        # Parcourir l'index:
        #  - _evenements.transaction_complete
        #  - _evenements.IDMGtransaction_traitee
        index = [
            ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                        Constantes.EVENEMENT_TRANSACTION_COMPLETE), 1),
            ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                           Constantes.EVENEMENT_TRANSACTION_TRAITEE), 1)
        ]
        # ordre_tri = index  # L'index est trie dans l'ordre necessaire

        # Filtre par transaction completee:
        #  - _evenements.transaction_complete = True
        #  - _evenements.IDMG.transaction_traitee existe
        filtre = {
            '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                       Constantes.EVENEMENT_TRANSACTION_COMPLETE): True,
            '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                          Constantes.EVENEMENT_TRANSACTION_TRAITEE): {'$exists': True}
        }

        if self.__transactions_a_ignorer:
            # Ajouter une liste de transactions a ignorer pour la regeneration
            # Ces transactions n'ont aucun impact sur l'etat des /documents
            libelle_domaine = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE)
            filtre[libelle_domaine] = {'$nin': self.__transactions_a_ignorer}

        return filtre, index

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        """
        Retourne un curseur Mongo avec les transactions a executer en ordre.
        :return:
        """
        if self.__complet:
            raise StopIteration()

        curseur = self.__preparer_curseur_transactions()
        for valeur in curseur:
            # self.__logger.debug("Transaction: %s" % str(valeur))
            yield valeur

        self.__complet = True

        return

    @property
    def gestionnaire(self):
        return self.__gestionnaire_domaine

    @property
    def _complet(self):
        return self.__complet


class GroupeurTransactionsSansEffet:

    def __init__(self):
        self.__complete = True

    def __iter__(self):
        return self

    def __next__(self):
        if self.__complete:
            raise StopIteration()

        self.__complete = True
        return


class TransactionTypeInconnuError(Exception):

    def __init__(self, msg, routing_key=None):
        if routing_key is not None:
            msg = '%s: %s' % (msg, routing_key)
        super().__init__(msg)
        self.routing_key = routing_key


class HandlerBackupDomaine:
    """
    Gestionnaire de backup des transactions d'un domaine.
    """

    def __init__(self, contexte, nom_domaine, nom_collection_transactions, nom_collection_documents):
        self._contexte = contexte
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._nom_domaine = nom_domaine
        self._nom_collection_transactions = nom_collection_transactions
        self._nom_collection_documents = nom_collection_documents

    def backup_domaine(self, heure: datetime.datetime, prefixe_fichier: str, entete_backup_precedent: dict):
        curseur = self._effectuer_requete_domaine(heure)

        # Utilise pour creer une chaine entre backups horaires
        chainage_backup_precedent = None
        if entete_backup_precedent:
            chainage_backup_precedent = {
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: entete_backup_precedent[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
                ConstantesBackup.LIBELLE_HACHAGE_ENTETE: self.calculer_hash_entetebackup(entete_backup_precedent)
            }

        heure_plusvieille = heure

        for transanter in curseur:
            self.__logger.debug("Vieille transaction : %s" % str(transanter))
            heure_anterieure = pytz.utc.localize(transanter['_id']['timestamp'])

            # Conserver l'heure la plus vieille dans ce backup
            # Permet de declencher backup quotidiens anterieurs
            if heure_plusvieille > heure_anterieure:
                heure_plusvieille = heure_anterieure

            # Creer le fichier de backup
            dependances_backup = self._backup_horaire_domaine(
                self._nom_collection_transactions,
                self._contexte.idmg,
                heure_anterieure,
                prefixe_fichier,
                Constantes.SECURITE_PRIVE,
                chainage_backup_precedent
            )

            catalogue_backup = dependances_backup.get('catalogue')
            if catalogue_backup is not None:
                hachage_entete = self.calculer_hash_entetebackup(catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE])
                uuid_transaction_catalogue = catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

                path_fichier_transactions = dependances_backup['path_fichier_backup']
                nom_fichier_transactions = path.basename(path_fichier_transactions)

                path_fichier_catalogue = dependances_backup['path_catalogue']
                nom_fichier_catalogue = path.basename(path_fichier_catalogue)

                self.__logger.debug("Information fichier backup:\n%s" % json.dumps(dependances_backup, indent=4, cls=BackupFormatEncoder))

                # Transferer vers consignation_fichier
                data = {
                    'timestamp_backup': int(heure_anterieure.timestamp()),
                    'fuuid_grosfichiers': json.dumps(catalogue_backup['fuuid_grosfichiers'])
                }

                # Preparer URL de connexion a consignationfichiers
                url_consignationfichiers = 'https://%s:%s' % (
                    self._contexte.configuration.serveur_consignationfichiers_host,
                    self._contexte.configuration.serveur_consignationfichiers_port,
                )

                with open(path_fichier_transactions, 'rb') as transactions_fichier:
                    with open(path_fichier_catalogue, 'rb') as catalogue_fichier:
                        files = {
                            'transactions': (nom_fichier_transactions, transactions_fichier, 'application/x-xz'),
                            'catalogue': (nom_fichier_catalogue, catalogue_fichier, 'application/x-xz'),
                        }

                        r = requests.put(
                            '%s/backup/domaine/%s' % (url_consignationfichiers, nom_fichier_catalogue),
                            data=data,
                            files=files,
                            verify=self._contexte.configuration.mq_cafile,
                            cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile)
                        )

                if r.status_code == 200:
                    reponse_json = json.loads(r.text)
                    self.__logger.debug("Reponse backup\nHeaders: %s\nData: %s" % (r.headers, str(reponse_json)))

                    # Verifier si le SHA3_512 du fichier de backup recu correspond a celui calcule localement
                    if reponse_json['fichiersDomaines'][nom_fichier_transactions] != \
                            catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_SHA3_512]:
                        raise ValueError(
                            "Le SHA3_512 du fichier de backup ne correspond pas a celui recu de consignationfichiers")

                    # Transmettre la transaction au domaine de backup
                    # L'enveloppe est deja prete, on fait juste l'emettre
                    self._contexte.message_dao.transmettre_nouvelle_transaction(catalogue_backup, None, None)

                    # Marquer les transactions comme inclue dans le backup
                    liste_uuids = dependances_backup['uuid_transactions']
                    self.marquer_transactions_backup_complete(self._nom_collection_transactions, liste_uuids)

                    transaction_sha512_catalogue = {
                        ConstantesBackup.LIBELLE_DOMAINE: self._nom_collection_transactions,
                        ConstantesBackup.LIBELLE_SECURITE: dependances_backup['catalogue'][ConstantesBackup.LIBELLE_SECURITE],
                        ConstantesBackup.LIBELLE_HEURE: int(heure_anterieure.timestamp()),
                        ConstantesBackup.LIBELLE_CATALOGUE_SHA3_512: dependances_backup[ConstantesBackup.LIBELLE_CATALOGUE_SHA3_512],
                        ConstantesBackup.LIBELLE_HACHAGE_ENTETE: hachage_entete,
                        Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transaction_catalogue,
                    }

                    self._contexte.generateur_transactions.soumettre_transaction(
                        transaction_sha512_catalogue, ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE_SHA3_512)

                else:
                    raise Exception("Reponse %d sur upload backup %s" % (r.status_code, nom_fichier_catalogue))

                # Calculer nouvelle entete
                entete_backup_precedent = catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
                chainage_backup_precedent = {
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: entete_backup_precedent[
                        Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
                    ConstantesBackup.LIBELLE_HACHAGE_ENTETE: hachage_entete
                }

            else:
                self.__logger.warning(
                    "Aucune transaction valide inclue dans le backup de %s a %s mais transactions en erreur presentes" % (
                        self._nom_collection_transactions, str(heure_anterieure))
                )

            # Traiter les transactions invalides
            liste_uuids_invalides = dependances_backup.get('liste_uuids_invalides')
            if liste_uuids_invalides and len(liste_uuids_invalides) > 0:
                self.__logger.error(
                    "Marquer %d transactions invalides exclue du backup de %s a %s" % (
                        len(liste_uuids_invalides), self._nom_collection_transactions, str(heure_anterieure))
                )
                self.marquer_transactions_invalides(self._nom_collection_transactions, liste_uuids_invalides)

        self.transmettre_trigger_jour_precedent(heure_plusvieille)

    def _effectuer_requete_domaine(self, heure: datetime.datetime):
        # Verifier s'il y a des transactions qui n'ont pas ete traitees avant la periode actuelle
        idmg = self._contexte.idmg

        filtre_verif_transactions_anterieures = {
            '_evenements.transaction_complete': True,
            '_evenements.%s' % Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG: False,
            '_evenements.transaction_traitee': {'$lt': heure},
        }
        regroupement_periode = {
            'year': {'$year': '$_evenements.transaction_traitee'},
            'month': {'$month': '$_evenements.transaction_traitee'},
            'day': {'$dayOfMonth': '$_evenements.transaction_traitee'},
            'hour': {'$hour': '$_evenements.transaction_traitee'},
        }
        regroupement = {
            '_id': {
                'timestamp': {
                    '$dateFromParts': regroupement_periode
                },
            },
        }
        sort = {'_id': 1}
        operation = [
            {'$match': filtre_verif_transactions_anterieures},
            {'$group': regroupement},
            {'$sort': sort},
        ]
        hint = {
            '_evenements.transaction_complete': 1,
            '_evenements.%s' % Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG: 1,
        }
        collection_transactions = self._contexte.document_dao.get_collection(self._nom_collection_transactions)

        return collection_transactions.aggregate(operation, hint=hint)

    def _backup_horaire_domaine(self, nom_collection_mongo: str, idmg: str, heure: datetime, prefixe_fichier: str, niveau_securite: str, chainage_backup_precedent: dict) -> dict:
        heure_str = heure.strftime("%Y%m%d%H")
        heure_fin = heure + datetime.timedelta(hours=1)
        self.__logger.debug("Backup collection %s entre %s et %s" % (nom_collection_mongo, heure, heure_fin))

        coltrans = self._contexte.document_dao.get_collection(nom_collection_mongo)
        label_tran = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE)
        label_backup = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG)
        filtre = {
            label_tran: True,
            label_backup: False,
        }
        sort = [
            ('_evenements.transaction_traitee', 1)
        ]
        hint = [
            (label_tran, 1),
            (label_backup, 1),
        ]

        curseur = coltrans.find(filtre, sort=sort, hint=hint)

        # Creer repertoire backup et determiner path fichier
        backup_workdir = self._contexte.configuration.backup_workdir
        Path(backup_workdir).mkdir(mode=0o700, parents=True, exist_ok=True)

        backup_nomfichier = '%s_transactions_%s_%s.json.xz' % (prefixe_fichier, heure_str, niveau_securite)
        path_fichier_backup = path.join(backup_workdir, backup_nomfichier)

        catalogue_nomfichier = '%s_catalogue_%s_%s.json.xz' % (prefixe_fichier, heure_str, niveau_securite)

        catalogue_backup = {
            ConstantesBackup.LIBELLE_DOMAINE: nom_collection_mongo,
            ConstantesBackup.LIBELLE_SECURITE: niveau_securite,
            ConstantesBackup.LIBELLE_HEURE: heure,

            ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER: catalogue_nomfichier,
            ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER: backup_nomfichier,
            ConstantesBackup.LIBELLE_TRANSACTIONS_SHA3_512: None,

            # Conserver la liste des certificats racine, intermediaire et noeud necessaires pour
            # verifier toutes les transactions de ce backup
            ConstantesBackup.LIBELLE_CERTS_RACINE: set(),
            ConstantesBackup.LIBELLE_CERTS_INTERMEDIAIRES: set(),
            ConstantesBackup.LIBELLE_CERTS: set(),
            ConstantesBackup.LIBELLE_CERTS_CHAINE_CATALOGUE: list(),

            # Conserver la liste des grosfichiers requis pour ce backup
            ConstantesBackup.LIBELLE_FUUID_GROSFICHIERS: dict(),

            ConstantesBackup.LIBELLE_BACKUP_PRECEDENT: chainage_backup_precedent,
        }

        # Ajouter le certificat du module courant pour etre sur
        enveloppe_certificat_module_courant = self._contexte.signateur_transactions.enveloppe_certificat_courant

        # Conserver la chaine de validation du catalogue
        certificats_validation_catalogue = [
            enveloppe_certificat_module_courant.fingerprint_ascii
        ]
        catalogue_backup[ConstantesBackup.LIBELLE_CERTS_CHAINE_CATALOGUE] = certificats_validation_catalogue

        certs_pem = {
            enveloppe_certificat_module_courant.fingerprint_ascii: enveloppe_certificat_module_courant.certificat_pem
        }
        catalogue_backup[ConstantesBackup.LIBELLE_CERTS_PEM] = certs_pem

        liste_enveloppes_cas = self._contexte.verificateur_certificats.aligner_chaine_cas(
            enveloppe_certificat_module_courant)
        for cert_ca in liste_enveloppes_cas:
            fingerprint_ca = cert_ca.fingerprint_ascii
            certificats_validation_catalogue.append(fingerprint_ca)
            certs_pem[fingerprint_ca] = cert_ca.certificat_pem

        liste_uuid_transactions = list()
        liste_uuids_invalides = list()
        info_backup = {
            'path_fichier_backup': path_fichier_backup,
            'uuid_transactions': liste_uuid_transactions,
            'liste_uuids_invalides': liste_uuids_invalides,
        }

        cles_set = ['certificats_racine', 'certificats_intermediaires', 'certificats', 'fuuid_grosfichiers']

        with lzma.open(path_fichier_backup, 'wt') as fichier:
            for transaction in curseur:
                uuid_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                try:
                    # Extraire metadonnees de la transaction
                    info_transaction = self._traiter_transaction(transaction, heure)
                    for cle in cles_set:
                        try:
                            catalogue_backup[cle].update(info_transaction[cle])
                        except KeyError:
                            pass

                    json.dump(transaction, fichier, sort_keys=True, ensure_ascii=True, cls=BackupFormatEncoder)

                    # Une transaction par ligne
                    fichier.write('\n')

                    # La transaction est bonne, on l'ajoute a la liste inclue dans le backup
                    liste_uuid_transactions.append(uuid_transaction)
                except HachageInvalide:
                    self.__logger.error("Transaction hachage invalide %s: transaction exclue du backup de %s" % (uuid_transaction, nom_collection_mongo))
                    # Marquer la transaction comme invalide pour backup
                    liste_uuids_invalides.append(uuid_transaction)
                except CertificatInvalide:
                    self.__logger.error("Erreur, certificat de transaction invalide : %s" % uuid_transaction)

        if len(liste_uuid_transactions) > 0:
            # Calculer SHA3-512 du fichier de backup des transactions
            sha512 = hashlib.sha3_512()
            with open(path_fichier_backup, 'rb') as fichier:
                sha512.update(fichier.read())
            sha512_digest = sha512.hexdigest()
            catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_SHA3_512] = sha512_digest
            catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER] = backup_nomfichier

            # Changer les set() par des list() pour extraire en JSON
            for cle in cles_set:
                if isinstance(catalogue_backup[cle], set):
                    catalogue_backup[cle] = list(catalogue_backup[cle])

            # Generer l'entete et la signature pour le catalogue
            catalogue_json = json.dumps(catalogue_backup, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)

            # Recharger le catalogue pour avoir le format exact (e.g. encoding dates)
            catalogue_backup = json.loads(catalogue_json)
            catalogue_backup = self._contexte.generateur_transactions.preparer_enveloppe(
                catalogue_backup, ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE)
            catalogue_json = json.dumps(catalogue_backup, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
            info_backup['catalogue'] = catalogue_backup

            # Sauvegarder catlogue sur disque pour transferer
            path_catalogue = path.join(backup_workdir, catalogue_nomfichier)
            info_backup['path_catalogue'] = path_catalogue

            with lzma.open(path_catalogue, 'wt') as fichier:
                # Dump du catalogue en format de transaction avec DateFormatEncoder
                fichier.write(catalogue_json)

            sha512 = hashlib.sha3_512()
            with open(path_catalogue, 'rb') as fichier:
                sha512.update(fichier.read())
            sha512_digest = sha512.hexdigest()
            info_backup[ConstantesBackup.LIBELLE_CATALOGUE_SHA3_512] = sha512_digest

        else:
            self.__logger.info("Backup: aucune transaction, backup annule")
            info_backup = {
                'liste_uuids_invalides': liste_uuids_invalides
            }

        return info_backup

    def _traiter_transaction(self, transaction, heure: datetime.datetime):
        """
        Verifie la signature de la transaction et extrait les certificats requis pour le backup.

        :param transaction:
        :return:
        """
        enveloppe_initial = self._contexte.verificateur_transaction.verifier(transaction)
        enveloppe = enveloppe_initial

        liste_enveloppes_cas = self._contexte.verificateur_certificats.aligner_chaine_cas(enveloppe_initial)

        # S'assurer que le certificat racine correspond a la transaction
        ca_racine = liste_enveloppes_cas[-1]
        if ca_racine.fingerprint_base58 != transaction['en-tete']['idmg']:
            raise ValueError("Transaction IDMG ne correspond pas au certificat racine " + enveloppe.fingerprint_base58)

        # Extraire liste de fingerprints
        liste_cas = [enveloppe.fingerprint_ascii for enveloppe in liste_enveloppes_cas]

        return {
            'certificats': [enveloppe_initial.fingerprint_ascii],
            'certificats_intermediaires': liste_cas[:-1],
            'certificats_racine': [liste_cas[-1]],
        }

    def marquer_transactions_backup_complete(self, nom_collection_mongo: str, uuid_transactions: list):
        """
        Marquer une liste de transactions du domaine comme etat inclues dans un backup horaire.

        :param nom_collection_mongo: Nom de la collection des transactions du domaine
        :param uuid_transactions: Liste des uuid de transactions (en-tete)
        :return:
        """

        evenement = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transactions,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_collection_mongo,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_TRANSACTION_BACKUP_HORAIRE_COMPLETE,
        }
        self._contexte.message_dao.transmettre_message(evenement, Constantes.TRANSACTION_ROUTING_EVENEMENT)

    def marquer_transactions_invalides(self, nom_collection_mongo: str, uuid_transactions: list):
        """
        Effectue une correction sur les transactions considerees invalides pour le backup. Ces transactions
        deja traitees sont dans un etat irrecuperable qui ne permet pas de les valider.

        :param nom_collection_mongo: Nom de la collection des transactions du domaine
        :param uuid_transactions: Liste des uuid de transactions (en-tete)
        :return:
        """

        evenement = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transactions,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_collection_mongo,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_TRANSACTION_BACKUP_ERREUR,
        }
        self._contexte.message_dao.transmettre_message(evenement, Constantes.TRANSACTION_ROUTING_EVENEMENT)

    def restaurer_domaines_horaires(self, nom_collection_mongo):

        url_consignationfichiers = 'https://%s:%s' % (
            self._contexte.configuration.serveur_consignationfichiers_host,
            self._contexte.configuration.serveur_consignationfichiers_port,
        )

        backup_workdir = self._contexte.configuration.backup_workdir
        Path(backup_workdir).mkdir(mode=0o700, parents=True, exist_ok=True)

        data = {
            'domaine': nom_collection_mongo
        }

        with requests.get(
                '%s/backup/liste/backups_horaire' % url_consignationfichiers,
                data=data,
                verify=self._contexte.configuration.mq_cafile,
                cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile)
        ) as r:

            if r.status_code == 200:
                reponse_json = json.loads(r.text)
            else:
                raise Exception("Erreur chargement liste backups horaire")

        self.__logger.debug("Reponse liste backups horaire:\n" + json.dumps(reponse_json, indent=4))

        for heure, backups in reponse_json['backupsHoraire'].items():
            self.__logger.debug("Telechargement fichiers backup %s" % heure)
            path_fichier_transaction = backups['transactions']
            nom_fichier_transaction = path.basename(path_fichier_transaction)

            with requests.get(
                    '%s/backup/horaire/transactions/%s' % (url_consignationfichiers, path_fichier_transaction),
                    verify=self._contexte.configuration.mq_cafile,
                    cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            ) as r:

                r.raise_for_status()

                # Sauvegarder le fichier
                with open(path.join(backup_workdir, nom_fichier_transaction), 'wb') as fichier:
                    for chunk in r.iter_content(chunk_size=8192):
                        fichier.write(chunk)

            path_fichier_catalogue = backups['catalogue']
            nom_fichier_catalogue = path.basename(path_fichier_catalogue)

            # Verifier l'integrite du fichier de transactions
            with lzma.open(path.join(backup_workdir, nom_fichier_catalogue), 'rt') as fichier:
                catalogue = json.load(fichier, object_hook=decoder_backup)

            self.__logger.debug("Verifier signature catalogue %s\n%s" % (nom_fichier_catalogue, catalogue))
            self._contexte.verificateur_transaction.verifier(catalogue)

            with requests.get(
                    '%s/backup/horaire/catalogues/%s' % (url_consignationfichiers, path_fichier_catalogue),
                    verify=self._contexte.configuration.mq_cafile,
                    cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            ) as r:

                r.raise_for_status()

                # Sauvegarder le fichier
                with open(path.join(backup_workdir, nom_fichier_catalogue), 'wb') as fichier:
                    for chunk in r.iter_content(chunk_size=8192):
                        fichier.write(chunk)

                    fichier.flush()

            # Catalogue ok, on verifie fichier de transactions
            self.__logger.debug("Verifier SHA3_512 sur le fichier de transactions %s" % nom_fichier_transaction)
            transactions_sha512 = catalogue[ConstantesBackup.LIBELLE_TRANSACTIONS_SHA3_512]
            sha512 = hashlib.sha3_512()
            with open(path.join(backup_workdir, nom_fichier_transaction), 'rb') as fichier:
                sha512.update(fichier.read())
            sha512_digest_calcule = sha512.hexdigest()

            if transactions_sha512 != sha512_digest_calcule:
                raise Exception(
                    "Le fichier de transactions %s est incorrect, SHA3_512 ne correspond pas a celui du catalogue" %
                    nom_fichier_transaction
                )

        # Une fois tous les fichiers telecharges et verifies, on peut commencer le
        # chargement dans la collection des transactions du domaine

        for heure, backups in reponse_json['backupsHoraire'].items():
            path_fichier_transaction = backups['transactions']
            nom_fichier_transaction = path.basename(path_fichier_transaction)

            with lzma.open(path.join(backup_workdir, nom_fichier_transaction), 'rt') as fichier:
                for transaction in fichier:
                    self.__logger.debug("Chargement transaction restauree vers collection:\n%s" % str(transaction))
                    # Emettre chaque transaction vers le consignateur de transaction
                    self._contexte.generateur_transactions.restaurer_transaction(transaction)

    def creer_backup_quoditien(self, domaine: str, jour: datetime.datetime):
        coldocs = self._contexte.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_pki = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)

        # Calculer la fin du jour comme etant le lendemain, on fait un "<" dans la selection
        fin_jour = jour + datetime.timedelta(days=1)

        # Faire la liste des catalogues de backups qui sont dus
        filtre_backups_quotidiens_dirty = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
            ConstantesBackup.LIBELLE_DOMAINE: domaine,
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            ConstantesBackup.LIBELLE_JOUR: {'$lt': fin_jour}
        }
        curseur_catalogues = coldocs.find(filtre_backups_quotidiens_dirty)
        plus_vieux_jour = jour

        for catalogue in curseur_catalogues:

            # S'assurer que le catalogue contient tous les certificats
            certs = catalogue[ConstantesBackup.LIBELLE_CERTS_RACINE].copy()
            certs.extend(catalogue[ConstantesBackup.LIBELLE_CERTS_INTERMEDIAIRES])
            certs.extend(catalogue[ConstantesBackup.LIBELLE_CERTS])

            # Identifier le plus vieux backup qui est effectue
            # Utilise pour transmettre trigger backup mensuel
            jour_backup = pytz.utc.localize(catalogue[ConstantesBackup.LIBELLE_JOUR])
            if plus_vieux_jour > jour_backup:
                plus_vieux_jour = jour_backup

            try:
                certs_pem = catalogue[ConstantesBackup.LIBELLE_CERTS_PEM]
            except KeyError:
                certs_pem = dict()
                catalogue[ConstantesBackup.LIBELLE_CERTS_PEM] = certs_pem

            # Ajouter le certificat du module courant pour etre sur
            enveloppe_certificat_module_courant = self._contexte.signateur_transactions.enveloppe_certificat_courant

            # Conserver la chaine de validation du catalogue
            certificats_validation_catalogue = [
                enveloppe_certificat_module_courant.fingerprint_ascii
            ]
            catalogue[ConstantesBackup.LIBELLE_CERTS_CHAINE_CATALOGUE] = certificats_validation_catalogue

            certs_pem[enveloppe_certificat_module_courant.fingerprint_ascii] = enveloppe_certificat_module_courant.certificat_pem

            liste_enveloppes_cas = self._contexte.verificateur_certificats.aligner_chaine_cas(enveloppe_certificat_module_courant)
            for cert_ca in liste_enveloppes_cas:
                fingerprint_ca = cert_ca.fingerprint_ascii
                certificats_validation_catalogue.append(fingerprint_ca)
                certs_pem[fingerprint_ca] = cert_ca.certificat_pem

            certs_manquants = set()
            for fingerprint in certs:
                if not certs_pem.get(fingerprint):
                    certs_manquants.add(fingerprint)

            self.__logger.debug("Liste de certificats a trouver: %s" % str(certs_manquants))

            if len(certs_manquants) > 0:
                filtre_certs_pki = {
                    ConstantesPki.LIBELLE_FINGERPRINT: {'$in': list(certs_manquants)},
                    # ConstantesPki.LIBELLE_CHAINE_COMPLETE: True,
                    Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                        ConstantesPki.LIBVAL_CERTIFICAT_ROOT,
                        ConstantesPki.LIBVAL_CERTIFICAT_INTERMEDIAIRE,
                        ConstantesPki.LIBVAL_CERTIFICAT_MILLEGRILLE,
                        ConstantesPki.LIBVAL_CERTIFICAT_NOEUD,
                    ]}
                }
                curseur_certificats = collection_pki.find(filtre_certs_pki)
                for cert in curseur_certificats:
                    fingerprint = cert[ConstantesPki.LIBELLE_FINGERPRINT]
                    pem = cert[ConstantesPki.LIBELLE_CERTIFICAT_PEM]
                    certs_pem[fingerprint] = pem
                    certs_manquants.remove(fingerprint)

                # Verifier s'il manque des certificats
                if len(certs_manquants) > 0:
                    raise Exception("Certificats manquants  dans backup domaine %s : %s" % (self._nom_domaine, str(certs_manquants)))

            # Filtrer catalogue pour retirer les champs Mongo
            for champ in catalogue.copy().keys():
                if champ.startswith('_') or champ in [ConstantesBackup.LIBELLE_DIRTY_FLAG]:
                    del catalogue[champ]

            # Generer l'entete et la signature pour le catalogue
            catalogue_json = json.dumps(catalogue, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
            catalogue = json.loads(catalogue_json)
            catalogue_quotidien = self._contexte.generateur_transactions.preparer_enveloppe(
                catalogue, ConstantesBackup.TRANSACTION_CATALOGUE_QUOTIDIEN)
            self.__logger.debug("Catalogue:\n%s" % catalogue_quotidien)

            # Transmettre le catalogue au consignateur de fichiers sous forme de commande. Ceci declenche la
            # creation de l'archive de backup. Une fois termine, le consignateur de fichier va transmettre une
            # transaction de catalogue quotidien.
            self._contexte.generateur_transactions.transmettre_commande(
                {'catalogue': catalogue_quotidien}, ConstantesBackup.COMMANDE_BACKUP_QUOTIDIEN)

        self.transmettre_trigger_mois_precedent(plus_vieux_jour)

    def creer_backup_mensuel(self, domaine: str, mois: datetime.datetime):
        coldocs = self._contexte.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_pki = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)

        # Calculer la fin du jour comme etant le lendemain, on fait un "<" dans la selection
        annee_fin = mois.year
        mois_fin = mois.month + 1
        if mois_fin > 12:
            annee_fin = annee_fin + 1
            mois_fin = 1
        fin_mois = datetime.datetime(year=annee_fin, month=mois_fin, day=1)

        # Faire la liste des catalogues de backups qui sont dus
        filtre_backups_mensuels_dirty = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_MENSUEL,
            ConstantesBackup.LIBELLE_DOMAINE: domaine,
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            ConstantesBackup.LIBELLE_MOIS: {'$lt': fin_mois}
        }
        curseur_catalogues = coldocs.find(filtre_backups_mensuels_dirty)
        plus_vieux_mois = mois

        for catalogue in curseur_catalogues:

            # Identifier le plus vieux backup qui est effectue
            # Utilise pour transmettre trigger backup mensuel
            mois_backup = pytz.utc.localize(catalogue[ConstantesBackup.LIBELLE_MOIS])
            if plus_vieux_mois > mois_backup:
                plus_vieux_mois = mois_backup

            # Ajouter le certificat du module courant pour etre sur de pouvoir valider le catalogue mensuel
            enveloppe_certificat_module_courant = self._contexte.signateur_transactions.enveloppe_certificat_courant

            try:
                certs_pem = catalogue[ConstantesBackup.LIBELLE_CERTS_PEM]
            except KeyError:
                certs_pem = dict()
                catalogue[ConstantesBackup.LIBELLE_CERTS_PEM] = certs_pem

            certificats_validation_catalogue = [
                enveloppe_certificat_module_courant.fingerprint_ascii
            ]
            catalogue[ConstantesBackup.LIBELLE_CERTS_CHAINE_CATALOGUE] = certificats_validation_catalogue

            certs_pem[enveloppe_certificat_module_courant.fingerprint_ascii] = enveloppe_certificat_module_courant.certificat_pem

            liste_enveloppes_cas = self._contexte.verificateur_certificats.aligner_chaine_cas(enveloppe_certificat_module_courant)
            for cert_ca in liste_enveloppes_cas:
                fingerprint_ca = cert_ca.fingerprint_ascii
                certificats_validation_catalogue.append(fingerprint_ca)
                certs_pem[fingerprint_ca] = cert_ca.certificat_pem

            # Filtrer catalogue pour retirer les champs Mongo
            for champ in catalogue.copy().keys():
                if champ.startswith('_') or champ in [ConstantesBackup.LIBELLE_DIRTY_FLAG]:
                    del catalogue[champ]

            # Generer l'entete et la signature pour le catalogue
            catalogue_json = json.dumps(catalogue, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
            catalogue = json.loads(catalogue_json)
            catalogue_mensuel = self._contexte.generateur_transactions.preparer_enveloppe(
                catalogue, ConstantesBackup.TRANSACTION_CATALOGUE_MENSUEL)
            self.__logger.debug("Catalogue:\n%s" % catalogue_mensuel)

            # Transmettre le catalogue au consignateur de fichiers sous forme de commande. Ceci declenche la
            # creation de l'archive de backup. Une fois termine, le consignateur de fichier va transmettre une
            # transaction de catalogue quotidien.
            self._contexte.generateur_transactions.transmettre_commande(
                {'catalogue': catalogue_mensuel}, ConstantesBackup.COMMANDE_BACKUP_MENSUEL)

        self.transmettre_trigger_annee_precedente(mois)

    def creer_backup_annuel(self, domaine: str, annee: datetime.datetime):
        pass

    def transmettre_trigger_jour_precedent(self, heure_plusvieille):
        """
        Determiner le jour avant la plus vieille transaction. On va transmettre un declencheur de
        backup quotidien, mensuel et annuel pour les aggregations qui peuvent etre generees

        :param heure_plusvieille:
        :return:
        """

        veille = heure_plusvieille - datetime.timedelta(days=1)
        veille = datetime.datetime(year=veille.year, month=veille.month, day=veille.day, tzinfo=datetime.timezone.utc)
        self.__logger.debug("Veille: %s" % str(veille))

        commande_backup_quotidien = {
            ConstantesBackup.LIBELLE_JOUR: int(veille.timestamp()),
            ConstantesBackup.LIBELLE_DOMAINE: self._nom_domaine,
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_quotidien,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_QUOTIDIEN.replace(
                '_DOMAINE_', self._nom_domaine),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
        )

    def transmettre_trigger_mois_precedent(self, jour: datetime.datetime):
        annee = jour.year
        mois_precedent = jour.month - 1
        if mois_precedent == 0:
            annee = annee - 1
            mois_precedent = 12

        mois_precedent = datetime.datetime(year=annee, month=mois_precedent, day=1, tzinfo=datetime.timezone.utc)

        commande_backup_mensuel = {
            ConstantesBackup.LIBELLE_MOIS: int(mois_precedent.timestamp()),
            ConstantesBackup.LIBELLE_DOMAINE: self._nom_domaine,
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_mensuel,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_MENSUEL.replace('_DOMAINE_', self._nom_domaine),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
        )

    def transmettre_trigger_annee_precedente(self, mois: datetime.datetime):
        annee_precedente = datetime.datetime(year=mois.year-1, month=1, day=1, tzinfo=datetime.timezone.utc)

        commande_backup_annuel = {
            ConstantesBackup.LIBELLE_ANNEE: int(annee_precedente.timestamp()),
            ConstantesBackup.LIBELLE_DOMAINE: self._nom_domaine,
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_annuel,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_ANNUEL.replace('_DOMAINE_', self._nom_domaine),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
        )

    def calculer_hash_entetebackup(self, entete):
        """
        Generer une valeur de hachage a partir de l'entete
        :param entete:
        :return:
        """
        hachage_backup = self._contexte.verificateur_transaction.hacher_contenu(entete, hachage=hashes.SHA3_512())
        return hachage_backup


class BackupHoraire(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        self.__logger.info("Processus backup horaire demarre, %s" % str(self.parametres))

        # Charger l'information du backup horaire precedent pour creer une chaine
        requete = {
            ConstantesBackup.LIBELLE_DOMAINE: self.controleur.gestionnaire.get_nom_domaine(),
            ConstantesBackup.LIBELLE_SECURITE: self.parametres[ConstantesBackup.LIBELLE_SECURITE],
        }
        self.set_requete(ConstantesBackup.REQUETE_BACKUP_DERNIERHORAIRE, requete)

        self.set_etape_suivante(BackupHoraire.executer_backup.__name__)

    def executer_backup(self):
        heure = pytz.utc.localize(self.parametres[ConstantesBackup.LIBELLE_HEURE])
        gestionnaire = self.controleur.gestionnaire
        domaine = gestionnaire.get_nom_domaine()

        entete_dernier_backup = self.parametres['reponse'][0]['dernier_backup']

        self.__logger.info("Reponse requete : %s" % str(entete_dernier_backup))

        gestionnaire.handler_backup.backup_domaine(heure, domaine, entete_dernier_backup)

        self.set_etape_suivante()  # Termine

        return {}
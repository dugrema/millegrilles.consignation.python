# Programme principal pour transferer les nouvelles transactions vers MongoDB

from millegrilles.dao.MessageDAO import JSONHelper, BaseCallback
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration

from millegrilles import Constantes
from bson.objectid import ObjectId
from threading import Thread, Event

import logging
import datetime
import traceback


class ConsignateurTransaction(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.json_helper = JSONHelper()
        self.message_handler = None
        self.__stop_event = Event()
        self.__channel = None

    def configurer_parser(self):
        super().configurer_parser()

        self.parser.add_argument(
            '--debug', action="store_true", required=False,
            help="Active le debugging (logger)"
        )

    # Initialise les DAOs, connecte aux serveurs.
    def initialiser(self, init_document=True, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)

        if self.args.debug:
            logging.getLogger('millegrilles.SecuritePKI').setLevel(logging.DEBUG)

        self.message_handler = ConsignateurTransactionCallback(self.contexte)

        # Executer la configuration pour RabbitMQ
        self.contexte.message_dao.register_channel_listener(self)
        # configurer_rabbitmq_thread = Thread(name="MQ-Configuration", target=self.callback_configurer_rabbitmq)
        # configurer_rabbitmq_thread.start()

        # Creer index: _mg-libelle
        collection = self.contexte.document_dao.get_collection(Constantes.COLLECTION_TRANSACTION_STAGING)
        collection.create_index([
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])
        # Index domaine, _mg-libelle
        collection.create_index([
            ('%s.%s' %
             (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
             1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])
        logging.info("Configuration et connection completee")

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel

        self.contexte.message_dao.configurer_rabbitmq()
        queue_name = self.contexte.configuration.queue_nouvelles_transactions
        channel.basic_consume(self.message_handler.callbackAvecAck, queue=queue_name, no_ack=False)
        # self.contexte.message_dao.demarrer_lecture_nouvelles_transactions(self.message_handler.callbackAvecAck)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def is_channel_open(self):
        return self.__channel is not None

    def executer(self):
        while not self.__stop_event.is_set():
            self.__stop_event.wait(3600)  # On fait juste attendre l'evenement de fermeture

    def deconnecter(self):
        self.__stop_event.set()
        self.contexte.document_dao.deconnecter()
        self.contexte.message_dao.deconnecter()
        logging.info("Deconnexion completee")


class ConsignateurTransactionCallback(BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        try:
            id_document = self.sauvegarder_nouvelle_transaction(message_dict, method.exchange)
            entete = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION]
            uuid_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
            domaine = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]

            # Copier properties utiles
            properties_mq = {}
            if properties.reply_to is not None:
                properties_mq['reply_to'] = properties.reply_to
            if properties.correlation_id is not None:
                properties_mq['correlation_id'] = properties.correlation_id

            self.contexte.message_dao.transmettre_evenement_persistance(
                id_document, uuid_transaction, domaine, properties_mq)
        except Exception as e:
            uuid_transaction = 'NA'
            en_tete = message_dict.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE)
            if en_tete is not None:
                uuid_transaction = en_tete.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)
            self._logger.exception(
                'Erreur traitement transaction uuid=%s, transferee a transaction.staging',
                uuid_transaction
            )
            message_traceback = traceback.format_exc()
            self.traiter_erreur_persistance(message_dict, e, message_traceback)
            raise e  # Relancer l'exception pour traitement independant

    def traiter_erreur_persistance(self, dict_message, error, message_traceback):
        document_staging = {
            'transaction': dict_message,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: {
                Constantes.EVENEMENT_DOCUMENT_PERSISTE: [datetime.datetime.now(tz=datetime.timezone.utc)]
            },
            'traceback': message_traceback,
            'erreur': {
                'message': str(error),
                'classe': error.__class__.__name__
            }

        }
        collection_erreurs = self.contexte.document_dao.get_collection(Constantes.COLLECTION_TRANSACTION_STAGING)
        collection_erreurs.insert_one(document_staging)

    @staticmethod
    def ajouter_evenement_transaction(contexte, id_transaction, nom_collection, evenement):
        collection_transactions = contexte.document_dao.get_collection(nom_collection)
        libelle_transaction_traitee = '%s.%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            contexte.configuration.nom_millegrille,
            evenement
        )
        selection = {Constantes.MONGO_DOC_ID: ObjectId(id_transaction)}
        operation = {
            '$push': {libelle_transaction_traitee: datetime.datetime.now(tz=datetime.timezone.utc)}
        }
        resultat = collection_transactions.update_one(selection, operation)

        if resultat.modified_count != 1:
            raise Exception("Erreur ajout evenement transaction: %s" % str(resultat))

    def sauvegarder_nouvelle_transaction(self, enveloppe_transaction, exchange):

        domaine_transaction = enveloppe_transaction[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE
        ][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE
        ]
        nom_collection = ConsignateurTransactionCallback.identifier_collection_domaine(domaine_transaction)
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        # Verifier la signature de la transaction
        enveloppe_certificat = self.contexte.verificateur_transaction.verifier(enveloppe_transaction)
        enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_ORIGINE] = \
            enveloppe_certificat.authority_key_identifier

        # Ajouter l'element evenements et l'evenement de persistance
        estampille = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]['estampille']
        # Changer estampille du format epoch en un format date et sauver l'evenement
        date_estampille = datetime.datetime.fromtimestamp(estampille)
        evenements = {
            Constantes.EVENEMENT_DOCUMENT_PERSISTE: [datetime.datetime.now(tz=datetime.timezone.utc)],
            Constantes.EVENEMENT_SIGNATURE_VERIFIEE: [datetime.datetime.now(tz=datetime.timezone.utc)]
        }
        enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT] = {
            Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE: date_estampille,
            self.contexte.configuration.nom_millegrille: evenements
        }

        resultat = collection_transactions.insert_one(enveloppe_transaction)
        doc_id = resultat.inserted_id

        return doc_id

    @staticmethod
    def identifier_collection_domaine(domaine):

        domaine_split = domaine.split('.')

        nom_collection = None
        if domaine_split[0] == 'millegrilles' and domaine_split[1] == 'domaines':
            nom_collection = '.'.join(domaine_split[0:3])

        return nom_collection

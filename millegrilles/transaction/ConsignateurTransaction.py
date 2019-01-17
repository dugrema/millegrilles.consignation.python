# Programme principal pour transferer les nouvelles transactions vers MongoDB

from millegrilles.dao.MessageDAO import JSONHelper, BaseCallback
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration

from millegrilles import Constantes
from bson.objectid import ObjectId

import logging
import datetime


class ConsignateurTransaction(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.json_helper = JSONHelper()
        self.message_handler = None

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
        self.contexte.message_dao.configurer_rabbitmq()

        # Creer index: _mg-libelle
        collection = self.contexte.document_dao.get_collection(Constantes.DOCUMENT_COLLECTION_TRANSACTIONS)
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

    def executer(self):
        # Note: la methode demarrer_... est blocking
        self.contexte.message_dao.demarrer_lecture_nouvelles_transactions(self.message_handler.callbackAvecAck)

    def deconnecter(self):
        self.contexte.document_dao.deconnecter()
        self.contexte.message_dao.deconnecter()
        logging.info("Deconnexion completee")

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        id_document = self.sauvegarder_nouvelle_transaction(self.contexte.document_dao._collection_transactions, message_dict)
        uuid_transaction = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        self.contexte.message_dao.transmettre_evenement_persistance(id_document, uuid_transaction, message_dict)


class ConsignateurTransactionCallback(BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte.configuration)
        self.contexte = contexte

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        id_document = self.sauvegarder_nouvelle_transaction(message_dict)
        uuid_transaction = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        self.contexte.message_dao.transmettre_evenement_persistance(id_document, uuid_transaction, message_dict)

    def ajouter_evenement_transaction(self, id_transaction, evenement):
        collection_transactions = self.contexte.document_dao.get_collection(Constantes.DOCUMENT_COLLECTION_TRANSACTIONS)
        libelle_transaction_traitee = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, evenement)
        selection = {Constantes.MONGO_DOC_ID: ObjectId(id_transaction)}
        operation = {
            '$push': {libelle_transaction_traitee: datetime.datetime.now(tz=datetime.timezone.utc)}
        }
        resultat = collection_transactions.update_one(selection, operation)

        if resultat.modified_count != 1:
            raise Exception("Erreur ajout evenement transaction: %s" % str(resultat))

    def sauvegarder_nouvelle_transaction(self, enveloppe_transaction):
        collection_transactions = self.contexte.document_dao.get_collection(Constantes.DOCUMENT_COLLECTION_TRANSACTIONS)

        # Verifier la signature de la transaction
        self.contexte.verificateur_transaction.verifier(enveloppe_transaction)

        # Ajouter l'element evenements et l'evenement de persistance
        estampille = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]['estampille']
        # Changer estampille du format epoch en un format date et sauver l'evenement
        date_estampille = datetime.datetime.fromtimestamp(estampille)
        enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT] = {
            Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE: [date_estampille],
            Constantes.EVENEMENT_DOCUMENT_PERSISTE: [datetime.datetime.now(tz=datetime.timezone.utc)]
        }

        resultat = collection_transactions.insert_one(enveloppe_transaction)
        doc_id = resultat.inserted_id

        return doc_id

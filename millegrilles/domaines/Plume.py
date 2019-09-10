# Domaine Plume - ecriture de documents
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.domaines.GrosFichiers import ConstantesGrosFichiers
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.dao.DocumentDAO import MongoJSONEncoder

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from base64 import b64encode, b64decode

import logging
import datetime
import os
import re


class ConstantesPlume:

    DOMAINE_NOM = 'millegrilles.domaines.Plume'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM

    LIBVAL_CONFIGURATION = 'configuration'

    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }


class GestionnairePlume(GestionnaireDomaine):

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

        self.initialiser_document(ConstantesPlume.LIBVAL_CONFIGURATION, ConstantesPlume.DOCUMENT_DEFAUT)

    def setup_rabbitmq(self, channel):

        # Queue message handlers
        self.__handler_transaction = TraitementTransactionPersistee(self)
        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_requetes_noeuds = TraitementRequetesNoeuds(self)

        nom_queue_transactions = '%s.%s' % (self.get_nom_queue(), 'transactions')
        nom_queue_ceduleur = '%s.%s' % (self.get_nom_queue(), 'ceduleur')
        nom_queue_processus = '%s.%s' % (self.get_nom_queue(), 'processus')
        nom_queue_requetes_noeuds = '%s.%s' % (self.get_nom_queue(), 'requete.noeuds')

        # Configurer la Queue pour les transactions
        def callback_init_transaction(queue, self=self, callback=self.__handler_transaction.callbackAvecAck):
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
        def callback_init_cedule(queue, self=self, callback=self.__handler_cedule.callbackAvecAck):
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
                routing_key='processus.domaine.%s.#' % ConstantesMaitreDesCles.DOMAINE_NOM,
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_processus,
            durable=False,
            callback=callback_init_processus,
        )

        # Queue pour les requetes de noeuds
        def callback_init_requetes_noeuds(queue, self=self, callback=self.__handler_requetes_noeuds.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_noeuds,
                queue=nom_queue_requetes_noeuds,
                routing_key='requete.%s.#' % ConstantesMaitreDesCles.DOMAINE_NOM,
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_requetes_noeuds,
            durable=False,
            callback=callback_init_requetes_noeuds,
        )

    def get_nom_queue(self):
        return ConstantesPlume.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesPlume.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesPlume.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPlume.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesPlume.DOMAINE_NOM


class TraitementMessageCedule(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


class TraitementTransactionPersistee(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


class TraitementRequetesNoeuds(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key

# Gestion des documents.
import json
import logging
import datetime

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from bson.objectid import ObjectId
from millegrilles import Constantes
from millegrilles.dao.ProcessusDocumentHelper import ProcessusHelper

'''
Data access object pour les documents dans MongoDB
'''


class MongoDAO:

    def __init__(self, configuration):
        self._configuration = configuration
        self._idmg = self._configuration.idmg

        self._client = None
        self._mg_database = None
        self._collection_transactions = None
        self._collection_processus = None
        self._collection_information_documents = None
        self._processus_document_helper = None

        self._logger = logging.getLogger("%s.MongoDAO" % __name__)

    def connecter(self):
        configuration_mongo = self._configuration.format_mongo_config()
        self._logger.debug("Connexion a MmongoDB\n%s" % str(configuration_mongo))

        self._client = MongoClient(**configuration_mongo)

        self._logger.debug("Verify if connection established")
        self._client.admin.command('ismaster')

        self._logger.info("Connection etablie, ouverture base de donnes %s" % self._configuration.idmg)

        self._mg_database = self._client[self._idmg]
        self._collection_processus = self._mg_database[Constantes.DOCUMENT_COLLECTION_PROCESSUS]
        self._collection_information_documents = self._mg_database[Constantes.DOCUMENT_COLLECTION_INFORMATION_DOCUMENTS]

        # Generer les classes Helper
        self._processus_document_helper = ProcessusHelper(self._mg_database)

    def deconnecter(self):
        if self._client is not None:
            client = self._client

            self._mg_database = None
            self._collection_processus = None
            self._collection_information_documents = None
            self._processus_document_helper = None

            client.close()

    '''
    Utiliser pour verifier si la connexion a Mongo fonctionne
    
    :returns: True si la connexion est live, False sinon.
    '''
    def est_enligne(self):
        if self._client is None:
            return False

        try:
            # The ismaster command is cheap and does not require auth.
            self._client.admin.command('ismaster')
            return True
        except ConnectionFailure:
            self._logger.info("Server not available")
            return False

    '''
    Chargement d'un document de transaction a partir d'un identificateur MongoDB
    
    :param id_doc: Numero unique du document dans MongoDB.
    :returns: Document ou None si aucun document ne correspond.
    '''
    def charger_transaction_par_id(self, id_doc, collection):
        if not isinstance(id_doc, ObjectId):
            id_doc = ObjectId(id_doc)
        return self.get_collection(collection).find_one({Constantes.MONGO_DOC_ID: id_doc})

    def charger_processus_par_id(self, id_doc, collection):
        return self.get_collection(collection).find_one({Constantes.MONGO_DOC_ID: ObjectId(id_doc)})

    def processus_helper(self):
        return self._processus_document_helper

    def get_collection(self, collection):
        return self._mg_database[collection]

    def get_database(self):
        return self._mg_database


class MongoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.timestamp()
        elif isinstance(obj, ObjectId):
            return str(obj)

        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)



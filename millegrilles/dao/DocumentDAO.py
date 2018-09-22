# Gestion des documents.

from pymongo import MongoClient
from bson.objectid import ObjectId
from millegrilles import Constantes
from millegrilles.dao.InformationDocumentHelper import InformationDocumentHelper
from millegrilles.dao.InformationGenereeDocumentHelper import InformationGenereeHelper
from millegrilles.dao.TransactionDocumentHelper import TransactionHelper
from millegrilles.dao.ProcessusDocumentHelper import ProcessusHelper

'''
Data access object pour les documents dans MongoDB
'''


class MongoDAO:

    def __init__(self, configuration):
        self._configuration = configuration
        self._nom_millegrille = "mg-%s" % self._configuration.nom_millegrille

        self._client = None
        self._mg_database = None
        self._collection_transactions = None
        self._collection_processus = None
        self._collection_information_documents = None
        self._transaction_document_helper = None
        self._information_document_helper = None
        self._information_generee_helper = None
        self._processus_document_helper = None

    def connecter(self):
        self._client = MongoClient(
            self._configuration.mongo_host,
            self._configuration.mongo_port,
            username=self._configuration.mongo_user,
            password=self._configuration.mongo_password)
        #print("Verify if connection established")
        self._client.admin.command('ismaster')

        #print("Connection etablie, ouverture base de donnes %s" % (self.nom_millegrille))

        self._mg_database = self._client[self._nom_millegrille]
        self._collection_transactions = self._mg_database[Constantes.DOCUMENT_COLLECTION_TRANSACTIONS]
        self._collection_processus = self._mg_database[Constantes.DOCUMENT_COLLECTION_PROCESSUS]
        self._collection_information_documents = self._mg_database[Constantes.DOCUMENT_COLLECTION_INFORMATION_DOCUMENTS]
        self._collection_information_generee = self._mg_database[Constantes.DOCUMENT_COLLECTION_INFORMATION_GENEREE]

        # Generer les classes Helper
        self._transaction_document_helper = TransactionHelper(self._mg_database)
        self._information_document_helper = InformationDocumentHelper(self._collection_information_documents)
        self._information_generee_helper = InformationGenereeHelper(self._mg_database)
        self._processus_document_helper = ProcessusHelper(self._mg_database)

    def deconnecter(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    '''
    Chargement d'un document de transaction a partir d'un identificateur MongoDB
    
    :param id_doc: Numero unique du document dans MongoDB.
    :returns: Document ou None si aucun document ne correspond.
    '''
    def charger_transaction_par_id(self, id_doc):
        return self._collection_transactions.find_one({Constantes.MONGO_DOC_ID: ObjectId(id_doc)})

    def charger_processus_par_id(self, id_doc):
        return self._collection_processus.find_one({Constantes.MONGO_DOC_ID: ObjectId(id_doc)})

    def transaction_helper(self):
        return self._transaction_document_helper

    def information_document_helper(self):
        return self._information_document_helper

    def information_generee_helper(self):
        return self._information_generee_helper

    def processus_helper(self):
        return self._processus_document_helper

    def collection_information_documents(self):
        return self._collection_information_documents

    def get_collection(self, collection):
        return self._mg_database[collection]

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
    Modifie un document de processus en ajoutant l'information de l'etape a la suite des autres etapes
    dans la liste du processus.
    
    :param id_document_processus: _id du document dans la collection processus.
    :param dict_etape: Dictionnaire complet a ajoute a la file des autres etapes.
    '''
    def sauvegarder_etape_processus(self, id_document_processus, dict_etape, etape_suivante=None):
        # Convertir id_document_process en ObjectId
        if isinstance(id_document_processus, ObjectId):
            id_document = {Constantes.MONGO_DOC_ID: id_document_processus}
        else:
            id_document = {Constantes.MONGO_DOC_ID: ObjectId(id_document_processus)}

        #print("$push vers mongo: %s --- %s" % (id_document, str(dict_etape)))
        set_operation = {}
        operation = {
            '$push': {Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPES: dict_etape},
        }
        if etape_suivante is None:
            operation['$unset'] = {Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE: ''}
        else:
            set_operation[Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE]=etape_suivante

        dict_etapes_parametres = dict_etape.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES)
        if dict_etapes_parametres is not None:
            for key, value in dict_etapes_parametres.items():
                complete_key = 'parametres.%s' % key
                set_operation[complete_key] = value

        if len(set_operation) > 0:
            operation['$set'] = set_operation

        resultat = self._collection_processus.update_one(id_document, operation)

        if resultat.modified_count != 1:
            raise ErreurMAJProcessus("Erreur MAJ processus: %s" % str(resultat))

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

class ErreurMAJProcessus(Exception):

    def __init__(self, message=None):
        super().__init__(message=message)


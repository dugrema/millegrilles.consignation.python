''' Gestion des documents.
'''

import time
from pymongo import MongoClient
from bson.objectid import ObjectId
from millegrilles import Constantes

'''
Data access object pour les documents dans MongoDB
'''


class MongoDAO:

    def __init__(self, configuration):
        self.configuration = configuration
        self.nom_millegrille = "mg-%s" % (self.configuration.nom_millegrille)

        self.client = None
        self.mg_database = None
        self.collection_transactions = None
        self.collection_processus = None

    def connecter(self):
        self.client = MongoClient(
            self.configuration.mongo_host,
            self.configuration.mongo_port,
            username=self.configuration.mongo_user,
            password=self.configuration.mongo_password)
        #print("Verify if connection established")
        self.client.admin.command('ismaster')

        #print("Connection etablie, ouverture base de donnes %s" % (self.nom_millegrille))

        self.mg_database = self.client[self.nom_millegrille]
        self.collection_transactions = self.mg_database["transactions"]
        self.collection_processus = self.mg_database["processus"]

    def deconnecter(self):
        if self.client is not None:
            self.client.close()
            self.client = None

    def sauvegarder_nouvelle_transaction(self, enveloppe_transaction):

        # Ajouter l'element evenements et l'evenement de persistance
        estampille = enveloppe_transaction['info-transaction']['estampille']
        enveloppe_transaction['evenements'] = {
            'transaction_nouvelle': [estampille],
            'transaction_persistance': [int(time.time())]
        }

        resultat = self.collection_transactions.insert_one(enveloppe_transaction)
        id = resultat.inserted_id
        return id

    '''
    Sauvegarde un nouveau document dans la collection de processus pour l'initialisation d'un processus.
    
    :param parametres: Parametres pour l'etape initiale.
    :returns: _id du nouveau document de processus
    '''
    def sauvegarder_initialisation_processus(self, moteur, nom_processus, parametres):
        document = {
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_MOTEUR: moteur,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS: nom_processus,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE: 'initiale',
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPES: [
                {
                    Constantes.PROCESSUS_DOCUMENT_LIBELLE_NOMETAPE: 'orientation',
                    Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES: parametres
                }
            ]
        }
        doc_id = self.collection_processus.insert_one(document)
        return doc_id.inserted_id

    '''
    Modifie un document de processus en ajoutant l'information de l'etape a la suite des autres etapes
    dans la liste du processus.
    
    :param id_document_processus: _id du document dans la collection processus.
    :param dict_etape: Dictionnaire complet a ajoute a la file des autres etapes.
    '''
    def sauvegarder_etape_processus(self, id_document_processus, dict_etape):
        # Convertir id_document_process en ObjectId
        if isinstance(id_document_processus, ObjectId):
            id_document = {Constantes.MONGO_DOC_ID: id_document_processus}
        else:
            id_document = {Constantes.MONGO_DOC_ID: ObjectId(id_document_processus)}

        operation = {'$push': {Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPES: dict_etape}}
        resultat = self.collection_processus.update_one(id_document, operation)

        if resultat.modified_count != 1:
            raise ErreurMAJProcessus("Erreur MAJ processus: %s" % str(resultat))

    '''
    Chargement d'un document de transaction a partir d'un identificateur MongoDB
    
    :param id_doc: Numero unique du document dans MongoDB.
    :returns: Document ou None si aucun document ne correspond.
    '''
    def charger_transaction_par_id(self, id_doc):
        return self.collection_transactions.find_one({Constantes.MONGO_DOC_ID: ObjectId(id_doc)})

    def charger_processus_par_id(self, id_doc):
        return self.collection_processus.find_one({Constantes.MONGO_DOC_ID: ObjectId(id_doc)})

class ErreurMAJProcessus(Exception):

    def __init__(self, message=None):
        super().__init__(message=message)


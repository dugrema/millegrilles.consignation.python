''' Gestion des documents.
'''

import time
from pymongo import MongoClient

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

    def deconnecter(self):
        self.client.close()
        self.client = None


    def sauvegarder_nouvelle_transaction(self, enveloppe_transaction):

        # Ajouter l'element evenements et l'evenement de persistance
        estampille = enveloppe_transaction['info-transaction']['estampille']
        enveloppe_transaction['evenements'] = {'transaction_nouvelle': [estampille], 'transaction_persistance': [int(time.time())]}

        resultat = self.collection_transactions.insert_one(enveloppe_transaction)
        id = resultat.inserted_id
        return id

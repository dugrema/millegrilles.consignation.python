''' Gestion des documents.
'''

import datetime
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
        self.client = MongoClient('dev2', 27017, username="root", password="example")
        print("Verify if connection established")
        self.client.admin.command('ismaster')

        print("Connection etablie, ouverture base de donnes %s" % (self.nom_millegrille))

        self.mg_database = self.client[self.nom_millegrille]
        self.collection_transactions = self.mg_database["transactions"]

    def deconnecter(self):
        self.client.close()
        self.client = None


    def sauvegarder_nouvelle_transaction(self, enveloppe_transaction):

        resultat = self.collection_transactions.insert_one(enveloppe_transaction)
        id = resultat.inserted_id
        return id

# Classe qui aide a creer et modifier les documents d'information generee.

import datetime

from millegrilles import Constantes
from bson.objectid import ObjectId

'''
Classe avec des methodes pour travailler dans la collection 'transactions'
'''


class TransactionHelper:

    def __init__(self, mongo_database):
        self._collection_transactions = mongo_database[Constantes.DOCUMENT_COLLECTION_TRANSACTIONS]

    def ajouter_evenement_transaction(self, id_transaction, evenement):
        libelle_transaction_traitee = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, evenement)
        selection = {Constantes.MONGO_DOC_ID: ObjectId(id_transaction)}
        operation = {
            '$push': {libelle_transaction_traitee: datetime.datetime.utcnow()}
        }
        resultat = self._collection_transactions.update_one(selection, operation)

        if resultat.modified_count != 1:
            raise Exception("Erreur ajout evenement transaction: %s" % str(resultat))


# Classe qui aide a creer et modifier les documents d'information generee.

import datetime

from millegrilles import Constantes
from bson.objectid import ObjectId
from millegrilles.SecuritePKI import VerificateurTransaction

'''
Classe avec des methodes pour travailler dans la collection 'transactions'
'''


class TransactionHelper:

    def __init__(self, mongo_database):
        self._collection_transactions = mongo_database[Constantes.DOCUMENT_COLLECTION_TRANSACTIONS]
        self._verificateur_transaction = VerificateurTransaction()


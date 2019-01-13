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
            '$push': {libelle_transaction_traitee: datetime.datetime.now(tz=datetime.timezone.utc)}
        }
        resultat = self._collection_transactions.update_one(selection, operation)

        if resultat.modified_count != 1:
            raise Exception("Erreur ajout evenement transaction: %s" % str(resultat))

    def sauvegarder_nouvelle_transaction(self, _collection_transactions, enveloppe_transaction):

        # Ajouter l'element evenements et l'evenement de persistance
        estampille = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]['estampille']
        # Changer estampille du format epoch en un format date
        date_estampille = datetime.datetime.fromtimestamp(estampille)
        enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT] = {
            Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE: [date_estampille],
            Constantes.EVENEMENT_DOCUMENT_PERSISTE: [datetime.datetime.now(tz=datetime.timezone.utc)]
        }

        resultat = _collection_transactions.insert_one(enveloppe_transaction)
        doc_id = resultat.inserted_id

        return doc_id

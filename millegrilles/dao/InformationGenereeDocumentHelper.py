# Classe qui aide a creer et modifier les documents d'information generee.

from millegrilles import Constantes

'''
Classe avec des methodes pour travailler dans la collection 'information-documents'
'''


class InformationGenereeHelper:

    def __init__(self, mongo_database):
        self._collection_information_documents = mongo_database[Constantes.DOCUMENT_COLLECTION_INFORMATION_DOCUMENTS]
        self._collection_information_generee = mongo_database[Constantes.DOCUMENT_COLLECTION_INFORMATION_GENEREE]

    def generer_rapport(self, selection, projection=None):
        cursor = self._collection_information_documents.find(selection, projection)
        return cursor

# Classe qui aide a creer et modifier les documents d'information generee.

from millegrilles import Constantes

'''
Classe avec des methodes pour travailler dans la collection 'information-documents'
'''


class InformationGenereeHelper:

    def __init__(self, mongo_database):
        self._collection_information_documents = mongo_database[Constantes.DOCUMENT_COLLECTION_INFORMATION_DOCUMENTS]
        self._collection_information_generee = mongo_database[Constantes.DOCUMENT_COLLECTION_INFORMATION_GENEREE]

    def executer_recherche(self, selection, projection=None):
        cursor = self._collection_information_documents.find(selection, projection)
        return cursor

    def sauvegarder_rapport(self, selection_rapport, document_resultat):

        if selection_rapport is None:
            raise ValueError('selection_rapport ne doit pas etre None')

        if document_resultat is None:
            raise ValueError('document_resultat ne doit pas etre None')

        # Sauvegarder / mettre a jour le rapport
        operation = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$set': document_resultat
        }

        print("Preparation sauvegarde selection: %s \nDocument: %s" % (selection_rapport, document_resultat))

        resultat = self._collection_information_generee.update_one(selection_rapport, operation, upsert=True)

        if resultat.matched_count == 0 and resultat.upserted_id is None:
            raise Exception("Erreur maj rapport, aucune insertion/maj (match:%d): %s" % (resultat.matched_count, selection))

        return resultat


    '''
    Methode qui fait une recherche distinct sur la 
    '''
    def executer_distinct_information_documents(self, champ, selection=None):
        resultat = self._collection_information_documents.distinct(champ, selection)
        return resultat

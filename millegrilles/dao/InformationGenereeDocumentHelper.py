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

    def sauvegarder_rapport(self, selection, document_resultat):
        # On prend le chemin tel quel et on ajoute 'rapport'
        selection[Constantes.DOCUMENT_INFODOC_CHEMIN].append('rapport')

        # Sauvegarder / mettre a jour le rapport
        operation = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$set': document_resultat
        }
        resultat = self._collection_information_generee.update_one(selection, operation, upsert=True)

        if resultat.matched_count == 0 and resultat.upserted_id is None:
            raise Exception("Erreur maj rapport, aucune insertion/maj (match:%d): %s" % (resultat.matched_count, selection))

        return resultat

    def executer_distinct(self, champ, selection=None):
        resultat = self._collection_information_documents.distinct(champ, selection)
        return resultat

# Module avec logique de gestion de la collection 'information-document'
from millegrilles import Constantes
from bson.objectid import ObjectId
import uuid
import datetime

'''
Classe avec des methodes pour travailler dans la collection 'information-documents'
'''
class InformationDocumentHelper:

    def __init__(self, collection_information_documents):
        self._collection_information_documents = collection_information_documents

    def charger_par_id(self, id_document):
        document = self._collection_information_documents.find_one({Constantes.MONGO_DOC_ID: ObjectId(id_document)})
        return document

    def ajouter_document(self, chemin, document):
        if chemin is None:
            raise Exception("Un information-document doit avoir un chemin")

        # Ajouter les meta-elements specifiques a cette collection
        document['_mg-chemin'] = chemin
        document['_mg-uuid-doc'] = str(uuid.uuid1())
        document['_mg-derniere-modification'] = datetime.datetime.utcnow()

        resultat = self._collection_information_documents.insert_one(document)
        id = resultat.inserted_id
        return id

    ''' Ajuste la date _mg-derniere-modification a maintenant. '''
    def touch_document(self, id_document):

        selection = {Constantes.MONGO_DOC_ID: ObjectId(id_document)}
        operation = {'$currentDate': {'_mg-derniere-modification': True}}

        resultat = self._collection_information_documents.update_one(selection, operation)
        if resultat.modified_count != 1:
            raise Exception("Erreur MAJ processus: %s" % str(resultat))

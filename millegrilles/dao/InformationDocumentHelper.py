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
        self._collection_information_documents.find_one({Constantes.MONGO_DOC_ID: ObjectId(id_document)})

    def ajouter_document(self, chemin, document):
        if chemin is None:
            raise Exception("Un information-document doit avoir un chemin")

        # Ajouter les meta-elements specifiques a cette collection
        document['_mg-chemin'] = chemin
        document['_mg-uuid-doc'] = uuid.uuid1()
        document['_mg-derniere-modification'] = datetime.datetime.utcnow()

        resultat = self._collection_information_documents.insert_one(document)
        id = resultat.inserted_id
        return id

    ''' Ajuste la date _mg-derniere-modification a maintenant. '''
    def touch_document(self, id_document):
        pass

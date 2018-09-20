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

    '''
    Ajoute un document a la collection information-document.
    
    :param chemin: Liste du chemin du document (path).
    :param document: Le document (dictionnaire) a ajouter.
    '''
    def ajouter_document(self, chemin, document):
        if chemin is None:
            raise Exception("Un information-document doit avoir un chemin")

        # Ajouter les meta-elements specifiques a cette collection
        document[Constantes.DOCUMENT_INFODOC_CHEMIN] = chemin
        document[Constantes.DOCUMENT_INFODOC_UUID] = str(uuid.uuid1())
        document[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = datetime.datetime.utcnow()

        resultat = self._collection_information_documents.insert_one(document)
        id = resultat.inserted_id
        return id

    ''' Ajuste la date _mg-derniere-modification a maintenant. '''
    def touch_document(self, id_document):

        selection = {Constantes.MONGO_DOC_ID: ObjectId(id_document)}
        operation = {'$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}}

        resultat = self._collection_information_documents.update_one(selection, operation)
        if resultat.modified_count != 1:
            raise Exception("Erreur touch _id-information-documents: %s" % id_document)

    '''
    Mise a jour de la collection information-documents. 
    
    :param id_document: _id du document dans la collection information-document
    :param valeurs_a_ajouter: Dictionnaire des valeurs a ajouter/modifier.
    :param valeurs_a_supprimer: Liste des valeurs (cles) a supprimer. 
    '''
    def maj_document(self, id_document, valeurs_a_ajouter=None, valeurs_a_supprimer=None):
        selection = {Constantes.MONGO_DOC_ID: ObjectId(id_document)}

        # Effectuer un touch sur la date de derniere modification
        operation = {'$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}}

        if valeurs_a_ajouter is not None:
            operation['$set'] = valeurs_a_ajouter

        if valeurs_a_supprimer is not None:
            valeurs_supprimer_dict = {}
            for val_sup in valeurs_a_supprimer:
                valeurs_supprimer_dict[val_sup] = ''
            operation['$unset'] = valeurs_supprimer_dict
        resultat = self._collection_information_documents.update_one(selection, operation)

        if resultat.modified_count != 1:
            raise Exception("Erreur touch _id-information-documents: %s" % id_document)

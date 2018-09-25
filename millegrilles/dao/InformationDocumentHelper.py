# Module avec logique de gestion de la collection 'information-document'
from millegrilles import Constantes
from bson.objectid import ObjectId
import uuid
import datetime

'''
Classe avec des methodes pour travailler dans la collection 'information-documents'
'''
class InformationDocumentHelper:

    def __init__(self, document_dao, message_dao):

        if document_dao is None:
            raise TypeError('document_dao ne doit pas etre None')

        if message_dao is None:
            raise TypeError('message_dao ne doit pas etre None')

        self._document_dao = document_dao
        self._message_dao = message_dao

        self._collection_information_documents = document_dao.get_collection(Constantes.DOCUMENT_COLLECTION_INFORMATION_DOCUMENTS)

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

        # Transmettre evenement
        self.transmettre_evenement(document, Constantes.EVENEMENT_DOCUMENT_AJOUTE, str(id))

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

        # Effectuer une maj sur la date de derniere modification
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
            raise Exception("Erreur maj _id-information-documents: %s" % id_document)

        # Transmettre evenement
        self.transmettre_evenement(selection, Constantes.EVENEMENT_DOCUMENT_MAJ, str(id_document))


    '''
    Mise a jour de la collection information-documents quand le _id est inconnu. 
    Le critere de selection  

    :param selection: Critere de selection qui va trouver le document a mettre a jour.
    :param valeurs_a_ajouter: Dictionnaire des valeurs a ajouter/modifier.
    :param valeurs_a_supprimer: Liste des valeurs (cles) a supprimer. 
    :param upsert: Si True, un nouveau document est cree s'il n'existe pas.
    '''

    def maj_document_selection(self, selection, valeurs_a_ajouter=None, valeurs_a_supprimer=None, upsert=False):
        if selection is None:
            raise TypeError('Le parametre selection ne peut pas etre None')

        if upsert and selection.get(Constantes.DOCUMENT_INFODOC_CHEMIN) is None:
            raise ValueError('Pour une operation qui peut resulter en upsert, il faut toujours fournir le chemin dans selection')

        # Effectuer une maj sur la date de derniere modification.
        operation = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        if upsert:
            # En cas de upsert, il faut s'assurer d'avoir tous les parametres necessaires
            # pour un document bien forme. Le _mg-chemin et _mg-derniere-modification sont deja assures.
            # Mais il faut inserer un nouveau uuid.
            operation['$setOnInsert'] = {Constantes.DOCUMENT_INFODOC_UUID: str(uuid.uuid1())}

        if valeurs_a_ajouter is not None:
            operation['$set'] = valeurs_a_ajouter

        if valeurs_a_supprimer is not None:
            valeurs_supprimer_dict = {}
            for val_sup in valeurs_a_supprimer:
                valeurs_supprimer_dict[val_sup] = ''
            operation['$unset'] = valeurs_supprimer_dict

        resultat = self._collection_information_documents.update_one(selection, operation, upsert)
        if resultat.matched_count == 0 and (upsert and resultat.upserted_id is None):
            raise Exception("Erreur maj contenu documents, aucune insertion/maj (match:%d): %s" % (resultat.matched_count, selection))

        upserted_id = None
        if resultat.upserted_id is not None:
            upserted_id = str(resultat.upserted_id)

        self.transmettre_evenement(selection, Constantes.EVENEMENT_DOCUMENT_MAJ, upserted_id)

        return resultat.upserted_id

    '''
    Inser un dictionnaire dans un document d'historique. Le document complet est conserve dans une liste.
    
    :param document: Valeurs a ajouter a l'historique (a la suite)
    :param timestamp: Date a utiliser pour _mg-estampille (devrait etre date effective de l'information)
    '''
    def inserer_historique_information_document(self, document, timestamp=datetime.datetime.utcnow()):

        document_historique = document.copy()
        document_historique['_mg-estampille'] = timestamp
        document_historique[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = datetime.datetime.utcnow()

        resultat = self._collection_information_documents.insert_one(document_historique)

        #selection_jour = selection.copy()
        #selection_jour['annee'] = timestamp.year
        #selection_jour['mois'] = timestamp.month
        #selection_jour['jour'] = timestamp.day

        #operation = {
        #    '$push': {'faits': document},
        #    '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        #}

        #resultat = self._collection_information_documents.update_one(selection_jour, operation, True)

        self.transmettre_evenement(document_historique, Constantes.EVENEMENT_DOCUMENT_AJOUTE, str(resultat.inserted_id))

        return resultat.inserted_id


    '''
    Verifie l'existance d'un document a partir d'un critere de selection.
    
    :param selection: Critere de selection MongoDB.
    '''
    def verifier_existance_document(self, selection):
        resultat = self._collection_information_documents.find_one(selection, '{_id: 1}')
        print("Resultat: %s" % str(resultat))
        return resultat is not None


    def transmettre_evenement(self, selection, evenement, id_document=None):
        if id_document is None:
            id_document = selection.get(Constantes.MONGO_DOC_ID)

        chemin = selection.get(Constantes.DOCUMENT_INFODOC_CHEMIN)

        message = {
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: evenement
        }

        if id_document is not None:
            message[Constantes.MONGO_DOC_ID] = id_document
        else:
            # Inclure l'information de selection au complet pour permettre de retrouver le document
            message.update(selection)

        if chemin is not None:
            message[Constantes.DOCUMENT_INFODOC_CHEMIN] = chemin

        self._message_dao.transmettre_evenement_generateur_documents(message)
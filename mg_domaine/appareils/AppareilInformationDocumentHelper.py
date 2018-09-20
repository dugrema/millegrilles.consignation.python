# Module avec logique de gestion de la collection 'information-document' pour le domaine appareils
from millegrilles import Constantes
from millegrilles.dao import InformationDocumentHelper
from bson.objectid import ObjectId


'''
Classe qui permet de creer et modifier des documents de la collection InformationDocument sous le chemin appareils.
'''
class AppareilInformationDocumentHelper(InformationDocumentHelper):

    def __init__(self, collection_information_documents):
        super().__init__(collection_information_documents)

    def chemin(self):
        return ['appareils']

    '''
    Ajoute ou modifie un document dans la collection information-document.
    
    Correspondance document existant: 
      - chemin = ['appareils', 'senseur', 'courant']
      - cle: {'senseur': no_senseur, 'noeud': noeud}

    :param chemin: Liste du chemin du document (path).
    :param document: Le document (dictionnaire) a ajouter.
    '''

    def sauvegarder_senseur_lecture(self, chemin, document):
        # S'assurer que le document a
        chemin.extend(['senseur', 'courant'])

        super().maj_document(chemin, document, upsert=True)

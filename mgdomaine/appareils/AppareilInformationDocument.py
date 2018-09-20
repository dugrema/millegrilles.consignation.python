# Module avec logique de gestion de la collection 'information-document' pour le domaine appareils
from millegrilles import Constantes
from millegrilles.dao.InformationDocumentHelper import InformationDocumentHelper
from bson.objectid import ObjectId


'''
Classe qui permet de creer et modifier des documents de la collection InformationDocument sous le chemin appareils.
'''
class AppareilInformationDocumentHelper(InformationDocumentHelper):

    def __init__(self, collection_information_documents):
        super().__init__(collection_information_documents)

    def chemin(self, sous_chemin=[]):
        chemin_complet = ['appareils']
        chemin_complet.extend(sous_chemin)
        return chemin_complet

    '''
    Ajoute ou modifie un document de lecture dans la collection information-document.
    
    Met aussi a jour le document d'historique pour ce senseur.
    
    Correspondance document existant: 
      - chemin = ['appareils', 'senseur', 'courant']
      - cle: {'senseur': senseur, 'noeud': noeud}

    :param chemin: Liste du chemin du document (path).
    :param lecture: Le document (dictionnaire) a ajouter.
    '''
    def sauvegarder_senseur_lecture(self, lecture):
        # S'assurer que le document a les cles necessaures: senseur et noeud
        if lecture.get('senseur') is None or lecture.get('noeud') is None:
            raise ValueError("La lecture doit avoir 'senseur', 'noeud' pour etre sauvegardee")

        # Verifier que la lecture a sauvegarder ne va pas ecraser une lecture plus recente pour le meme senseur

        chemin_complet = self.chemin(['senseur', 'courant'])
        selection = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: chemin_complet,
            'noeud': lecture['noeud'],
            'senseur': lecture['senseur']
        }
        super().maj_document_selection(selection, lecture, upsert=True)

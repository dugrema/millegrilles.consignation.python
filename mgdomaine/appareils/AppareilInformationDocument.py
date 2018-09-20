# Module avec logique de gestion de la collection 'information-document' pour le domaine appareils
from millegrilles import Constantes
from millegrilles.dao.InformationDocumentHelper import InformationDocumentHelper
from bson.objectid import ObjectId
import datetime


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

        if lecture.get('temps_lecture') is None:
            raise ValueError('La lecture doit fournir le temps original de lecture (temps-lect)')

        temps_lect = datetime.datetime.fromtimestamp(lecture['temps_lecture'])

        # Preparer le critere de selection de la lecture. Utilise pour trouver le document courant et pour l'historique
        selection = {
            'noeud': lecture['noeud'],
            'senseur': lecture['senseur']
        }

        # Verifier que la lecture a sauvegarder ne va pas ecraser une lecture plus recente pour le meme senseur
        selection_verif_plusrecent = selection.copy()
        selection_verif_plusrecent[Constantes.DOCUMENT_INFODOC_CHEMIN] = self.chemin(['senseur', 'courant'])
        selection_verif_plusrecent['temps_lecture'] = {'$gte': lecture['temps_lecture']}
        document_plusrecent_existe = self.verifier_existance_document(selection_verif_plusrecent)

        if not document_plusrecent_existe:
            # Enregistrer cette lecture comme courante (plus recente)
            selection_courant = selection.copy()
            selection_courant[Constantes.DOCUMENT_INFODOC_CHEMIN] = self.chemin(['senseur', 'courant'])
            self.maj_document_selection(selection_courant, lecture, upsert=True)

        # Ajouter la lecture au document d'historique
        selection_historique = selection.copy()
        selection_historique[Constantes.DOCUMENT_INFODOC_CHEMIN] = self.chemin(['senseur', 'historique'])
        self.inserer_historique_quotidien_selection(selection_historique, lecture, timestamp=temps_lect)


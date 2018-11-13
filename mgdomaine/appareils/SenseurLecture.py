# Module avec logique de gestion de la collection 'information-document' pour le domaine appareils
import datetime

from millegrilles import Constantes
from millegrilles.dao.InformationDocumentHelper import InformationDocumentHelper
from millegrilles.processus.MGProcessus import MGProcessusTransaction
from millegrilles.rapport.GenerateurRapports import GenerateurRapportParGroupe, GenerateurRapportParAggregation


'''
Classe qui permet de creer et modifier des documents de la collection InformationDocument sous le chemin appareils.
'''
class AppareilInformationDocumentHelper(InformationDocumentHelper):

    def __init__(self, document_dao, message_dao):
        super().__init__(document_dao, message_dao)

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
      
    Element temporel (historique et courant): temps_lecture

    :param chemin: Liste du chemin du document (path).
    :param lecture: Le document (dictionnaire) a ajouter.
    '''
    def sauvegarder_senseur_lecture(self, lecture):
        # S'assurer que le document a les cles necessaires: senseur et noeud
        if lecture.get('senseur') is None or lecture.get('noeud') is None:
            raise ValueError("La lecture doit avoir 'senseur', 'noeud' pour etre sauvegardee")

        if lecture.get('temps_lecture') is None:
            raise ValueError('La lecture doit fournir le temps original de lecture (temps_lecture)')

        # Ajouter la lecture au document d'historique
        document_historique = lecture.copy()
        document_historique[Constantes.DOCUMENT_INFODOC_CHEMIN] = self.chemin(['senseur', 'lecture', 'historique'])
        temps_lect = datetime.datetime.fromtimestamp(lecture['temps_lecture'])
        self.inserer_historique_information_document(document_historique, timestamp=temps_lect)

        # Preparer le critere de selection de la lecture. Utilise pour trouver le document courant et pour l'historique
        selection = {
            'noeud': lecture['noeud'],
            'senseur': lecture['senseur']
        }
        chemin_courant = self.chemin(['senseur', 'lecture', 'courant'])

        # Verifier que la lecture a sauvegarder ne va pas ecraser une lecture plus recente pour le meme senseur
        selection_verif_plusrecent = selection.copy()
        selection_verif_plusrecent[Constantes.DOCUMENT_INFODOC_CHEMIN] = chemin_courant
        selection_verif_plusrecent['temps_lecture'] = {'$gte': lecture['temps_lecture']}
        document_plusrecent_existe = self.verifier_existance_document(selection_verif_plusrecent)

        if not document_plusrecent_existe:
            # Enregistrer cette lecture comme courante (plus recente)
            selection_courant = selection.copy()
            selection_courant[Constantes.DOCUMENT_INFODOC_CHEMIN] = chemin_courant
            self.maj_document_selection(selection_courant, lecture, upsert=True)

class GenerateurPagesNoeudsSenseurs(GenerateurRapportParGroupe):

    def __init__(self, document_dao):
        super().__init__(document_dao)

        # Chemin pour le rapport dans la collection des documents generes
        self.set_chemin_destination(['appareils', 'senseur', 'lecture', 'noeud'])

        # Document source pour le rapport.
        # Chemin = apppareils, senseur, courant
        # groupe (page) = noeud  (nom du noeud/machine qui enregistre les lectures)
        # ligne = senseur  (id unique pour un noeud)
        self.set_source(
            chemin=['appareils', 'senseur', 'lecture', 'courant'],
            groupe='noeud',
            ligne='senseur'
        )

    '''
    Le trigger pour generer la page est toute modification a un document sur le chemin.
    '''
    def traiter_evenement(self, evenement):
        chemin_evenement = evenement.get(Constantes.DOCUMENT_INFODOC_CHEMIN)
        return self._source[Constantes.DOCUMENT_INFODOC_CHEMIN] == chemin_evenement


class GenerateurPagesNoeudsStatistiquesDernierJour(GenerateurRapportParAggregation):

    def __init__(self, document_dao):
        selection = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: ['appareils', 'senseur', 'lecture', 'historique']
        }

        regroupement_champs = {
            'temperature-maximum': {'$max': '$temperature'},
            'temperature-minimum': {'$min': '$temperature'},
            'humidite-maximum': {'$max': '$humidite'},
            'humidite-minimum': {'$min': '$humidite'},
            'pression-maximum': {'$max': '$pression'},
            'pression-minimum': {'$min': '$pression'}
        }

        super().__init__(document_dao, selection, regroupement_champs)

        # Chemin pour le rapport dans la collection des documents generes
        self.set_chemin_destination(['appareils', 'senseur', 'historique', 'rapport', 'dernierjour'])

        # CLEANUP/AMELIORATION - les valeurs suivantes devraient etre utilisees dans le rapport d'aggretation, a faire.

        # Document source pour le rapport.
        # Chemin = apppareils, senseur, courant
        # groupe (page) = noeud  (nom du noeud/machine qui enregistre les lectures)
        # ligne = senseur  (id unique pour un noeud)
        self.set_source(
            chemin=['appareils', 'senseur', 'lecture', 'historique'],
            groupe=['noeud', 'senseur']
        )

    '''
    Le trigger pour generer la page est toute modification a un document sur le chemin.
    '''
    def traiter_evenement(self, evenement):
        chemin_evenement = evenement.get(Constantes.DOCUMENT_INFODOC_CHEMIN)
        #return self._source[Constantes.DOCUMENT_INFODOC_CHEMIN] == chemin_evenement
        return False # Le trigger n'existe pas encore (cedule)


class GenerateurPagesNoeudsStatistiquesDernierMois(GenerateurRapportParAggregation):

    def __init__(self, document_dao):
        selection = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: ['appareils', 'senseur', 'lecture', 'historique']
        }

        regroupement_champs = {
            'temperature-maximum': {'$max': '$temperature'},
            'temperature-minimum': {'$min': '$temperature'},
            'humidite-maximum': {'$max': '$humidite'},
            'humidite-minimum': {'$min': '$humidite'},
            'pression-maximum': {'$max': '$pression'},
            'pression-minimum': {'$min': '$pression'}
        }

        super().__init__(document_dao, selection, regroupement_champs, niveau_aggregation=GenerateurRapportParAggregation.NIVEAU_AGGREGATION_JOUR)

        # Chemin pour le rapport dans la collection des documents generes
        self.set_chemin_destination(['appareils', 'senseur', 'historique', 'rapport', 'derniermois'])

        # CLEANUP/AMELIORATION - les valeurs suivantes devraient etre utilisees dans le rapport d'aggretation, a faire.

        # Document source pour le rapport.
        # Chemin = apppareils, senseur, courant
        # groupe (page) = noeud  (nom du noeud/machine qui enregistre les lectures)
        # ligne = senseur  (id unique pour un noeud)
        self.set_source(
            chemin=['appareils', 'senseur', 'lecture', 'historique'],
            groupe=['noeud', 'senseur']
        )

    '''
    Le trigger pour generer la page est toute modification a un document sur le chemin.
    '''
    def traiter_evenement(self, evenement):
        chemin_evenement = evenement.get(Constantes.DOCUMENT_INFODOC_CHEMIN)
        # return self._source[Constantes.DOCUMENT_INFODOC_CHEMIN] == chemin_evenement
        return False # Le trigger n'existe pas encore (cedule)


'''
Processus pour importer une lecture dans MilleGrilles.
'''
class ProcessusSenseurConserverLecture(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def dao_helper(self):
        helper = AppareilInformationDocumentHelper(self._controleur.document_dao(), self._controleur.message_dao())
        return helper

    def initiale(self):
        helper = self.dao_helper()
        transaction = self.charger_transaction()

        lecture = transaction['charge-utile']

        # Verifier que le noeud est fourni - sinon on utilie le nom de domaine d'origine de la transaction
        if lecture.get('noeud') is None:
            # On va utiliser l'information de source du message pour donner un nom implicite au noeud.
            # Normalement ca va etre le nom de domaine: mathieu@cuisine.maple.mdugre,info, on garde cuisine.maple.mdugre.info
            source = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_SOURCE_SYSTEME]
            source = source.split('@')[1]
            lecture['noeud'] = source

        helper.sauvegarder_senseur_lecture(lecture)

        # Terminer
        self.set_etape_suivante()

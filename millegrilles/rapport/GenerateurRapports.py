# Module de generateurs de rapports

from millegrilles import Constantes

'''
Un generateur de rapport sert a faire l'entretien d'un document ou groupe de documents dans la collection
information-generee.
'''


class GenerateurRapport:

    def __init__(self, document_dao):

        if document_dao is None:
            raise ValueError('document_dao ne doit pas etre None')
        self._document_dao = document_dao

        # datetime de la derniere execution
        self._derniere_execution = None

        # dictionnaire decrivant la source de documents pour les rapports
        self._source = None

        # chemin a sauvegarder pour les rapports
        self._chemin_destination = None

        # la frequence a laquelle on a declencher un rafraichissement complet des documents
        self._frequence_rafraichissement = None

        # indique s'il faut rafraichir les rapports a chaque redemarrage de la MilleGrille
        self._rafraichir_au_demarrage = True

        # projection a utiliser pour reduire la quantite de donnees a traiter
        self._projection = None

        # liste ordonnee des transformations a appliquer sur chaque ligne
        self._transformations = None

    def set_source(self, chemin, ligne, groupe=None):
        self._source = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: chemin,
            'ligne': ligne
        }
        if groupe is not None:
            self._source['groupe'] = groupe

    def generer(self):

        information_generee_helper = self._document_dao.information_generee_helper()

        if self._source.get('groupe') is not None:
            pass # Il faut faire une requete qui va sortir la liste complete des groupes

        selection = dict()
        selection[Constantes.DOCUMENT_INFODOC_CHEMIN] = self._source[Constantes.DOCUMENT_INFODOC_CHEMIN]

        resultats = []
        with information_generee_helper.executer_recherche(selection) as cursor:
            for document in cursor:
                resultats.append(document)

        document_genere = {'senseurs': resultats}


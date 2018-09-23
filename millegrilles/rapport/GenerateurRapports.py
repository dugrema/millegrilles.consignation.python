# Module de generateurs de rapports

import datetime
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
        self._information_generee_helper = self._document_dao.information_generee_helper()

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

    def generer(self):
        raise NotImplemented('La methode doit etre redefinie par une sous-classe')

    def set_source(self, chemin, ligne=Constantes.MONGO_DOC_ID, groupe=None):
        self._source = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: chemin,
            'ligne': ligne
        }
        if groupe is not None:
            self._source['groupe'] = groupe

    def identifier_groupes_rapport(self):
        chemin = self._source[Constantes.DOCUMENT_INFODOC_CHEMIN]

        # Il faut faire une requete qui va sortir la liste complete des groupes
        champs_groupe = self._source['groupe']
        selection_groupes = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: chemin
        }
        groupes = self._information_generee_helper.executer_distinct_information_documents(
            champs_groupe,
            selection=selection_groupes)

        return groupes

    def set_chemin_destination(self, valeur=None):
        self._chemin_destination = valeur


class GenerateurRapportParGroupe(GenerateurRapport):

    def __init__(self, document_dao):
        super().__init__(document_dao)

    def generer(self):

        selection_rapport = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: self._chemin_destination
        }

        if self._source.get('groupe') is not None:
            groupes = self.identifier_groupes_rapport()

            for groupe in groupes:
                document = self.generer_document_groupe(groupe)

                # Creer selection pour trouver le document existant ou le creer avec les valeurs appropriees
                selection_rapport_groupe = selection_rapport.copy()
                selection_rapport_groupe[self._source['groupe']] = groupe

                self._information_generee_helper.sauvegarder_rapport(selection_rapport_groupe, document)
        else:
            # Il n'y a pas de groupes, on appelle la methode pour generer le document une seule fois
            document = self.generer_document_groupe()
            self._information_generee_helper.sauvegarder_rapport(selection_rapport, document)

    def generer_document_groupe(self, groupe=None):

        selection = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: self._source[Constantes.DOCUMENT_INFODOC_CHEMIN]
        }

        if groupe is not None:
            selection[self._source['groupe']] = groupe

        cle_ligne =  self._source['ligne']
        resultats = dict()
        with self._information_generee_helper.executer_recherche(selection) as cursor:
            for document in cursor:
                cle_ligne_valeur = str(document[cle_ligne])
                resultats[cle_ligne_valeur] = document

        print('Document genere pour groupe %s: %s' % (groupe, resultats))
        return resultats


class GenerateurRapportParAggregation(GenerateurRapport):

    # Constantes pour cette classe
    NIVEAU_AGGREGATION_HEURE = 'heure'
    NIVEAU_AGGREGATION_JOUR = 'jour'

    def __init__(self, document_dao):
        super().__init__(document_dao)

        self._selection = None
        self._champs_regroupement = None

        self._champ_date = '_mg-estampille'
        self._niveau_aggregation = GenerateurRapportParAggregation.NIVEAU_AGGREGATION_HEURE
        self._date_reference = datetime.datetime.now()


    '''
     Methode pour generer des documents de rapport par aggregation sur un champ temporel.
    
     :param selection: Dictionnaire qui permet de filtrer les documents a utiliser.
     :param champs_regroupement: Dictionnaire qui correspond a la clause du $group
     :param champ_date: Le champ de date ISO sur lequel faire le regroupement
     :param niveau_aggregation: Utiliser une des constantes NIVEAU_ de cette classe
     :param date_reference: Date de reference (fin de periode) a utiliser pour ce rapport.
     '''
    def generer_document_aggregation_periode(
            self,
            selection,
            champs_regroupement,
            champ_date='_mg-estampille',
            niveau_aggregation=NIVEAU_AGGREGATION_HEURE,
            date_reference=datetime.datetime.now()):
        # Creer fenetre 24h / 30 jours

        if niveau_aggregation == GenerateurRapportParAggregation.NIVEAU_AGGREGATION_HEURE:
            time_range_to = datetime.datetime(date_reference.year, date_reference.month, date_reference.day,
                                              date_reference.hour)
            time_range_from = time_range_to - datetime.timedelta(days=1)
        elif niveau_aggregation == GenerateurRapportParAggregation.NIVEAU_AGGREGATION_JOUR:
            time_range_to = datetime.datetime(date_reference.year, date_reference.month, date_reference.day)
            time_range_from = time_range_to - datetime.timedelta(days=30)
        else:
            raise ValueError("niveau_aggregation n'est pas supporte: %s" % niveau_aggregation)

        selection_date = selection.copy()
        selection_date[champ_date] = {'$gte': time_range_from, '$lt': time_range_to}

        champ_date_var = '$%s' % champ_date

        regroupement_periode = {
            'year': {'$year': champ_date_var},
            'month': {'$month': champ_date_var},
            'day': {'$dayOfMonth': champ_date_var}
        }

        if niveau_aggregation == GenerateurRapportParAggregation.NIVEAU_AGGREGATION_HEURE:
            regroupement_periode['hour'] = {'$hour': champ_date_var}

        regroupement = {
            '_id': {
                'noeud': '$noeud',
                'senseur': '$senseur',
                'periode': {
                    '$dateFromParts': regroupement_periode
                }
            }
        }

        regroupement.update(champs_regroupement)

        operation = [
            {'$match': selection_date},
            {'$group': regroupement}
        ]

        resultat = self._information_generee_helper.executer_regroupement_information_documents(operation)
        print("Document resultats groupement par noeud: %s" % str(resultat))

        return resultat

    def generer(self):

        selection_rapport = {
            Constantes.DOCUMENT_INFODOC_CHEMIN: self._chemin_destination
        }

        if self._source.get('groupe') is not None:
            groupes = self.identifier_groupes_rapport()

            for groupe in groupes:
                document = self.generer_document_groupe(groupe)

                # Creer selection pour trouver le document existant ou le creer avec les valeurs appropriees
                selection_rapport_groupe = selection_rapport.copy()
                selection_rapport_groupe[self._source['groupe']] = groupe

                self._information_generee_helper.sauvegarder_rapport(selection_rapport_groupe, document)
        else:
            # Il n'y a pas de groupes, on appelle la methode pour generer le document une seule fois
            document = self.generer_document_groupe()
            self._information_generee_helper.sauvegarder_rapport(selection_rapport, document)
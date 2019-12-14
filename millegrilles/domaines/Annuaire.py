from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

import datetime
import uuid
import logging


class AnnuaireConstantes:

    DOMAINE_NOM = 'millegrilles.domaines.Annuaire'
    QUEUE_SUFFIXE = DOMAINE_NOM
    COLLECTION_TRANSACTIONS_NOM = QUEUE_SUFFIXE
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM

    LIBVAL_INDEX_MILLEGRILLES = 'index.millegrilles'
    LIBVAL_FICHE_TIERCE = 'fiche.tierce'
    LIBVAL_FICHE_PRIVEE = 'fiche.privee'      # Fiche privee de la millegrille locale
    LIBVAL_FICHE_PUBLIQUE = 'fiche.publique'  # Fiche publique de la millegrille locale signee par le maitredescles

    LIBELLE_DOC_LISTE = 'liste'
    LIBELLE_DOC_SECURITE = '_securite'
    LIBELLE_DOC_LIENS_PUBLICS = 'public'
    LIBELLE_DOC_LIENS_PRIVES = 'prive'
    LIBELLE_DOC_USAGER = 'usager'
    LIBELLE_DOC_CERTIFICAT_RACINE = 'certificat_racine'
    LIBELLE_DOC_CERTIFICAT_FULLCHAIN = 'certificat_fullchain'
    LIBELLE_DOC_CERTIFICAT_ADDITIONNELS = 'certificats_additionnels'
    LIBELLE_DOC_EXPIRATION_INSCRIPTION = 'expiration_inscription'
    LIBELLE_DOC_ABONNEMENTS = 'abonnements'

    TEMPLATE_DOCUMENT_INDEX_MILLEGRILLES = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_INDEX_MILLEGRILLES,
        LIBELLE_DOC_LISTE: list(),
    }

    TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_PRIVEE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_FICHE_PRIVEE,
    }

    TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_PUBLIQUE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_FICHE_PUBLIQUE,
    }

    TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_TIERCE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_FICHE_TIERCE,
        Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: None,
        LIBELLE_DOC_LIENS_PUBLICS: list(),
        LIBELLE_DOC_LIENS_PRIVES: list(),
        LIBELLE_DOC_USAGER: dict(),
        LIBELLE_DOC_CERTIFICAT_RACINE: None,     # str
        LIBELLE_DOC_CERTIFICAT_FULLCHAIN: None,  # Liste certificats du maitredescles + intermediaires
        LIBELLE_DOC_CERTIFICAT_ADDITIONNELS: None,  # Liste de certificats maitredescles additionnels
        LIBELLE_DOC_SECURITE: Constantes.SECURITE_PROTEGE,
        LIBELLE_DOC_EXPIRATION_INSCRIPTION: None,  # Date d'expiration du certificat
        LIBELLE_DOC_ABONNEMENTS: dict(),  # Dict d'abonnements pour cette MilleGrille
    }


class GestionnaireAnnuaire(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None

    def configurer(self):
        super().configurer()

        # collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        #
        # collection_domaine.create_index(
        #     [
        #         (AnnuaireConstantes.LIBELLE_DOMAINE, 1),
        #         (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        #     ],
        #     name='domaine-mglibelle'
        # )

    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(TachesConstantes.LIBVAL_NOTIFICATIONS, TachesConstantes.DOC_NOTIFICATIONS)

    def get_nom_queue(self):
        return AnnuaireConstantes.QUEUE_SUFFIXE

    def get_nom_collection(self):
        return AnnuaireConstantes.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return AnnuaireConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return AnnuaireConstantes.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return AnnuaireConstantes.DOMAINE_NOM

    def traiter_cedule(self, message):
        timestamp_message = message['timestamp']['UTC']
        if timestamp_message[4] % 6 == 0:
            self._logger.debug("Executer entretien annuaire (6 heures)")
            # Declencher la verification des actions sur taches

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == '':
            processus = "millegrilles_domaines_Annuaire:ProcessusNotificationRecue"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus


class ProcessusTaches(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return AnnuaireConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return AnnuaireConstantes.COLLECTION_PROCESSUS_NOM


class ProcessusNotificationRecue(ProcessusTaches):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine

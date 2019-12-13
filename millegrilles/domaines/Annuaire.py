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

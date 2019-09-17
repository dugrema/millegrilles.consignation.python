# Test du regenerateur de transactions
from millegrilles import Constantes
from millegrilles.Domaines import GroupeurTransactionsARegenerer, GestionnaireDomaine
from millegrilles.MGProcessus import MGPProcesseurRegeneration
from millegrilles.util.BaseMongo import BaseMongo

from millegrilles.domaines.GrosFichiers import ConstantesGrosFichiers, GestionnaireGrosFichiers
from millegrilles.domaines.MaitreDesCles import GestionnaireMaitreDesCles
from millegrilles.domaines.SenseursPassifs import GestionnaireSenseursPassifs
from millegrilles.domaines.Principale import GestionnairePrincipale
from millegrilles.domaines.Plume import GestionnairePlume
from millegrilles.domaines.Parametres import GestionnaireParametres
from millegrilles.domaines.Pki import GestionnairePki

import logging

logging.basicConfig()
logging.getLogger('RegenererTest').setLevel(logging.DEBUG)
logging.getLogger('millegrilles.Domaines.RegenerateurDeDocuments').setLevel(logging.DEBUG)
logging.getLogger('millegrilles.Domaines.GroupeurTransactionsARegenerer').setLevel(logging.DEBUG)


class RegenererTest(BaseMongo):

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger('RegenererTest')
        self.logger.setLevel(logging.DEBUG)

    def liste_documents_gros_fichiers(self):
        nom_millegrille = self.contexte.configuration.nom_millegrille
        gestionnaire_grosfichiers = GestionnaireGrosFichiers(self.contexte)
        groupeur = GroupeurTransactionsARegenerer(gestionnaire_grosfichiers)
        for transactions in groupeur:
            self.logger.debug("Nombre de transactions: %s" % str(transactions.count()))
            for transaction in transactions:
                self.logger.debug("Transaction _id:%s, transaction_traitee: %s" % (
                    str(transaction['_id']),
                    str(transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT][nom_millegrille][Constantes.EVENEMENT_TRANSACTION_TRAITEE]))
                )

    def regenerer_grosfichiers(self):
        gestionnaire_grosfichiers = GestionnaireGrosFichiers(self.contexte)
        processus_controleur = MGPProcesseurRegeneration(self.contexte, gestionnaire_grosfichiers)
        processus_controleur.regenerer_documents()

    def regenerer_maitredescles(self):
        gestionnaire_maitredescles = GestionnaireMaitreDesCles(self.contexte)
        processus_controleur = MGPProcesseurRegeneration(self.contexte, gestionnaire_maitredescles)
        processus_controleur.regenerer_documents()

    def regenerer_senseurspassifs(self):
        gestionnaire_senseurspassifs = GestionnaireSenseursPassifs(self.contexte)
        processus_controleur = MGPProcesseurRegeneration(self.contexte, gestionnaire_senseurspassifs)
        processus_controleur.regenerer_documents()

    def regenerer_principale(self):
        gestionnaire_principale = GestionnairePrincipale(self.contexte)
        processus_controleur = MGPProcesseurRegeneration(self.contexte, gestionnaire_principale)
        processus_controleur.regenerer_documents()

    def regenerer_plume(self):
        gestionnaire_plume = GestionnairePlume(self.contexte)
        processus_controleur = MGPProcesseurRegeneration(self.contexte, gestionnaire_plume)
        processus_controleur.regenerer_documents()

    def regenerer_parametres(self):
        gestionnaire_parametres = GestionnaireParametres(self.contexte)
        processus_controleur = MGPProcesseurRegeneration(self.contexte, gestionnaire_parametres)
        processus_controleur.regenerer_documents()

    def regenerer_pki(self):
        gestionnaire_pki = GestionnairePki(self.contexte)
        processus_controleur = MGPProcesseurRegeneration(self.contexte, gestionnaire_pki)
        processus_controleur.regenerer_documents()

    def test(self):
        # self.liste_documents_gros_fichiers()

        # self.regenerer_grosfichiers()
        # self.regenerer_maitredescles()
        # self.regenerer_senseurspassifs()
        # self.regenerer_principale()
        # self.regenerer_plume()
        # self.regenerer_parametres()
        self.regenerer_pki()  # Tester que rien n'arrive - pas pret avant inter


class MockGestionnaire(GestionnaireDomaine):

    def __init__(self, contexte):
        super().__init__(contexte=contexte)

    def get_collection_transaction_nom(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

    def get_nom_collection(self):
        return ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM

    def get_collection(self):
        return self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

# ---- MAIN ----
regenererTest = RegenererTest()
regenererTest.test()


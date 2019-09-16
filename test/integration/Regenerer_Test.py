# Test du regenerateur de transactions
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles import Constantes
from millegrilles.domaines.GrosFichiers import ConstantesGrosFichiers
from millegrilles.Domaines import GroupeurTransactionsARegenerer, RegenerateurDeDocuments
from millegrilles.util.BaseMongo import BaseMongo
import logging

logging.basicConfig()
logging.getLogger('RegenererTest').setLevel(logging.DEBUG)
logging.getLogger('millegrilles.Domaines.RegenerateurDeDocuments').setLevel(logging.DEBUG)
logging.getLogger('millegrilles.Domaines.GroupeurTransactionsARegenerer').setLevel(logging.DEBUG)


class RegenererTest(BaseMongo):

    def __init__(self):
        super().__init__()
        self.mock_gestionnaire = MockGestionnaire(self.contexte)
        self.logger = logging.getLogger('RegenererTest')
        self.logger.setLevel(logging.DEBUG)

    def liste_documents_gros_fichiers(self):
        nom_millegrille = self.contexte.configuration.nom_millegrille
        groupeur = GroupeurTransactionsARegenerer(self.mock_gestionnaire)
        for transactions in groupeur:
            self.logger.debug("Nombre de transactions: %s" % str(transactions.count()))
            for transaction in transactions:
                self.logger.debug("Transaction _id:%s, transaction_traitee: %s" % (
                    str(transaction['_id']),
                    str(transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT][nom_millegrille][Constantes.EVENEMENT_TRANSACTION_TRAITEE]))
                )

    def regenerer_grosfichiers(self):
        regenerateur = RegenerateurDeDocuments(self.mock_gestionnaire)
        regenerateur.regenerer_documents()

    def test(self):
        # self.liste_documents_gros_fichiers()
        self.regenerer_grosfichiers()


class MockGestionnaire:

    def __init__(self, contexte):
        self.contexte = contexte

    def get_collection_transaction_nom(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

    def get_nom_collection(self):
        return ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM

    def get_collection(self):
        return self.contexte.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

# ---- MAIN ----
regenererTest = RegenererTest()
regenererTest.test()


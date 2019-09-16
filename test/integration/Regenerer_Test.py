# Test du regenerateur de transactions
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles import Constantes
from millegrilles.domaines.GrosFichiers import ConstantesGrosFichiers
from millegrilles.Domaines import GroupeurTransactionsARegenerer
from millegrilles.util.BaseMongo import BaseMongo
import logging

logging.basicConfig()
logging.getLogger('RegenererTest').setLevel(logging.DEBUG)
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

    def test(self):
        self.liste_documents_gros_fichiers()


class MockGestionnaire:

    def __init__(self, contexte):
        self.contexte = contexte

    def get_collection_transactions(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM


# ---- MAIN ----
regenererTest = RegenererTest()
regenererTest.test()


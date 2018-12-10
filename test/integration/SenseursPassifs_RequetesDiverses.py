# Classe utilisee pour faire diverses requetes sur les senseurs passifs (test).
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.MessageDAO import PikaDAO
from mgdomaines.appareils import TraitementBacklogLecturesSenseursPassifs


class SenseursPassifsRequetesTest:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()
        print("Connection MongDB")
        self.document_dao = MongoDAO(self.configuration)
        self.document_dao.connecter()
        print("Connecter Pika")
        self.message_dao = PikaDAO(self.configuration)
        self.message_dao.connecter()

        self._traitement = TraitementBacklogLecturesSenseursPassifs(self.message_dao, self.document_dao)

    def run_requete_plusrecentetransactionlecture_parsenseur(self):
        return self._traitement.run_requete_plusrecentetransactionlecture_parsenseur()

    def run_requete_genererdeclencheur_parsenseur(self, liste_senseurs):
        self._traitement.run_requete_genererdeclencheur_parsenseur(liste_senseurs)

### MAIN ###

test = SenseursPassifsRequetesTest()
liste_transactions = test.run_requete_plusrecentetransactionlecture_parsenseur()
test.run_requete_genererdeclencheur_parsenseur(liste_transactions)
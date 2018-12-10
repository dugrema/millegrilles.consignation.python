from mgdomaines.appareils.AffichagesPassifs import AfficheurSenseurPassifTemperatureHumiditePression
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
import time
import traceback


class AfficheurSenseurPassifTemperatureHumiditePressionTest(AfficheurSenseurPassifTemperatureHumiditePression):

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()
        self.document_dao = MongoDAO(self.configuration)
        self.document_dao.connecter()  # Tester reconnexion

        self.document_ids = ['5bf98475a9f65540c1bcc016']

        super().__init__(self.configuration, self.document_dao, document_ids=self.document_ids, intervalle_secs=5)

    def test(self):
        for document_id in self.get_documents():
            print("Document charge: %s" % str(self._documents[document_id]))

        while True:
            if not self.document_dao.est_enligne():
                try:
                    self.document_dao.connecter()
                    print("TEST: Connexion a Mongo etablie")
                except Exception as ce:
                    print("Erreur reconnexion Mongo: %s" % str(ce))
                    traceback.print_exc()

            time.sleep(10)

    def maj_affichage(self, lignes_affichage):
        super().maj_affichage(lignes_affichage)

        # print("maj_affichage: (%d lignes) = %s" % (len(lignes_affichage), str(lignes_affichage)))

        for no in range(0, len(lignes_affichage)):
            print("maj_affichage Ligne %d: %s" % (no+1, str(lignes_affichage[no])))


# Demarrer test

test = AfficheurSenseurPassifTemperatureHumiditePressionTest()
try:
    print("Test debut")
    test.start()

    test.test()

    print("Test termine")
except Exception as e:
    print("Erreur main: %s" % e)
    traceback.print_exc()
finally:
    test.fermer()
    test._document_dao.deconnecter()

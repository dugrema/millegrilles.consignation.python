from mgdomaines.appareils.AffichagesPassifs import AfficheurDocumentMAJDirecte
from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
from millegrilles.dao.DocumentDAO import MongoDAO
from bson import ObjectId
import time
from threading import Thread


class AfficheurDocumentMAJDirecteTest(AfficheurDocumentMAJDirecte):

    def __init__(self):
        contexte = ContexteRessourcesMilleGrilles()

        print("contexte.initialiser()")
        contexte.initialiser(init_document=False)
        print("ioloop MQ")
        self.thread_ioloop = Thread(name="MQ-ioloop", target=contexte.message_dao.run_ioloop)
        self.thread_ioloop.start()

        print("super.init")
        super().__init__(contexte, intervalle_secs=5)

    def liste_senseurs(self):
        return [2, 3, 17]

    def get_filtre(self):
        filtre = {
            "_mg-libelle": "senseur.individuel",
            "senseur": {
                "$in": [int(senseur) for senseur in self.liste_senseurs()]
            }
        }
        return filtre

    def test(self):
        for document_id in self.get_documents():
            print("Document charge: %s" % str(self._documents[document_id]))

    def test_deconnecter_reconnecter(self):
        self.reconnecter()
        self.reconnecter()


# Demarrer test

test = AfficheurDocumentMAJDirecteTest()
try:
    print("Test debut")
    test.start()
    # test.test_deconnecter_reconnecter()

    for i in range(0, 30):
        test.test()
        time.sleep(1)

    print("Test termine")
except Exception as e:
    print("Erreur main: %s" % e)
finally:
    test.fermer()

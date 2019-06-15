from mgdomaines.appareils.AffichagesPassifs import AfficheurDocumentMAJDirecte
from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
from millegrilles.dao.DocumentDAO import MongoDAO
from bson import ObjectId
import time


class AfficheurDocumentMAJDirecteTest(AfficheurDocumentMAJDirecte):

    def __init__(self):
        contexte = ContexteRessourcesMilleGrilles()
        contexte.initialiser(init_document=False)
        super().__init__(contexte, intervalle_secs=5)

    def get_filtre(self):
        return ["5c42605524fb4ce929db094e"]

    def test(self):
        for document_id in self.get_documents():
            print("Document charge: %s" % str(self._documents[document_id]))


# Demarrer test

test = AfficheurDocumentMAJDirecteTest()
try:
    print("Test debut")
    test.start()

    for i in range(0, 30):
        test.test()
        time.sleep(1)

    print("Test termine")
except Exception as e:
    print("Erreur main: %s" % e)
finally:
    test.fermer()

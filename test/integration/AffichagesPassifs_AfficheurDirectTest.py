from mgdomaines.appareils.AffichagesPassifs import AfficheurDocumentMAJDirecte
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from bson import ObjectId
import time


class AfficheurDocumentMAJDirecteTest(AfficheurDocumentMAJDirecte):

    def __init__(self):
        configuration = TransactionConfiguration()
        configuration.loadEnvironment()
        document_dao = MongoDAO(configuration)
        document_dao.connecter()
        super().__init__(configuration, document_dao, intervalle_secs=5)

    def get_collection(self):
        return self._document_dao.get_collection('mathieu')

    def get_filtre(self):
        return {"_id": {'$in': [ObjectId("5bf80ce3e597dd0008fe557b")]}}

    def test(self):
        for document_id in self.get_documents():
            print("Document charge: %s" % str(self._documents[document_id]))


# Demarrer test

test = AfficheurDocumentMAJDirecteTest()
try:
    print("Test debut")
    test.start()

    test.test()
    time.sleep(16)

    print("Test termine")
except Exception as e:
    print("Erreur main: %s" % e)
finally:
    test.fermer()
    test._document_dao.deconnecter()

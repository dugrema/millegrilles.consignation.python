from mgdomaines.appareils.AffichagesPassifs import AfficheurDocumentMAJDirecte
from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
from millegrilles.dao.DocumentDAO import MongoDAO
from bson import ObjectId
import time
import logging

from threading import Thread

from millegrilles.Constantes import SenseursPassifsConstantes


class AfficheurDocumentMAJDirecteTest(AfficheurDocumentMAJDirecte):

    def __init__(self):
        contexte = ContexteRessourcesMilleGrilles()

        print("contexte.initialiser()")
        contexte.initialiser()
        print("ioloop MQ")
        self.thread_ioloop = Thread(name="MQ-ioloop", target=contexte.message_dao.run_ioloop)
        self.thread_ioloop.start()

        print("super.init")
        super().__init__(contexte, intervalle_secs=5)

    def liste_senseurs(self):
        return [2, 3, 17]

    def test(self):
        for document_id in self.get_documents():
            print("Document charge: %s" % str(self._documents[document_id]))

    def test_deconnecter_reconnecter(self):
        self.reconnecter()
        self.reconnecter()


# Demarrer test
logging.basicConfig(level=logging.WARNING)
logging.getLogger('millegrilles').setLevel(logging.INFO)
logging.getLogger('mgdomaines.appareils').setLevel(logging.DEBUG)

logger = logging.getLogger('__main__')

test = AfficheurDocumentMAJDirecteTest()
try:
    print("Test debut")
    test.start()
    # test.test_deconnecter_reconnecter()

    time.sleep(3600)  # Actif 1 heure

    # for i in range(0, 30):
    #     test.test()
    #     time.sleep(1)

    print("Test termine")
except Exception as e:
    logger.exception("Erreur main: %s" % e)
finally:
    test.fermer()

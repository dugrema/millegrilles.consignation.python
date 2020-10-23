from mgdomaines.appareils.AffichagesPassifs import AfficheurDocumentMAJDirecte, AffichageAvecConfiguration
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

    def test(self):
        for document_id in self.get_documents():
            print("Document charge: %s" % str(self._documents[document_id]))
        try:
            print("Test debut")
            test.start()

            time.sleep(3600)  # Actif 1 heure

            print("Test termine")
        except Exception as e:
            logger.exception("Erreur main: %s" % e)
        finally:
            self.fermer()


class AffichageAvecConfigurationTest(AffichageAvecConfiguration):

    def __init__(self):
        contexte = ContexteRessourcesMilleGrilles()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__logger.info("contexte.initialiser()")
        contexte.initialiser()

        self.__logger.info("ioloop MQ")
        self.thread_ioloop = Thread(name="MQ-ioloop", target=contexte.message_dao.run_ioloop)
        self.thread_ioloop.start()

        self.__logger.info("super.init")
        super().__init__(contexte, intervalle_secs=5)

    def maj_affichage(self, lignes_affichage):
        super().maj_affichage(lignes_affichage)
        for ligne in lignes_affichage:
            print("LIGNE : '%s' (backlight:%s)" % (ligne, self._affichage_actif))

    def test(self):
        try:
            self.__logger.info("Test debut")
            test.start()
            time.sleep(3600)  # Actif 1 heure
            self.__logger.info("Test termine")
        except Exception as e:
            logger.exception("Erreur main")
        finally:
            self.fermer()


# Demarrer test
logging.basicConfig(level=logging.WARNING)
logging.getLogger('millegrilles').setLevel(logging.INFO)
logging.getLogger('mgdomaines.appareils').setLevel(logging.DEBUG)

logger = logging.getLogger('__main__')

# Test simple
#test = AfficheurDocumentMAJDirecteTest()
#test.test()

# Test avec affichage simule dans log, thread
test = AffichageAvecConfigurationTest()
test.test()

import logging

from mgdomaines.appareils.AffichagesPassifs import AfficheurSenseurPassifTemperatureHumiditePression
from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
import time
import traceback


class AfficheurSenseurPassifTemperatureHumiditePressionTest(AfficheurSenseurPassifTemperatureHumiditePression):

    def __init__(self):
        contexte = ContexteRessourcesMilleGrilles()
        print("contexte.initialiser()")
        contexte.initialiser()

        # self.document_ids = ['514951f2f43211e99259b827eb53ee51']
        self.noeud_id = '909155d3-1dd2-4870-823c-83e9e25e8b11'

        super().__init__(contexte, noeud_id=self.noeud_id, timezone_horloge='America/Toronto', intervalle_secs=5)

    def test(self):
        for document_id in self.get_documents():
            print("Document charge: %s" % str(self._documents[document_id]))

        while True:
            time.sleep(10)

    def maj_affichage(self, lignes_affichage):
        super().maj_affichage(lignes_affichage)

        # print("maj_affichage: (%d lignes) = %s" % (len(lignes_affichage), str(lignes_affichage)))

        for no in range(0, len(lignes_affichage)):
            print("maj_affichage Ligne %d: %s" % (no+1, str(lignes_affichage[no])))


# Demarrer test

logging.basicConfig()
logging.getLogger('mgdomaines').setLevel(logging.DEBUG)

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
    test.contexte.deconnecter()

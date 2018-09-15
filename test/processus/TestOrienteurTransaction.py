import unittest
from millegrilles.processus.OrienteurTransaction import OrienteurTransaction
from millegrilles.processus.OrienteurTransaction import ErreurInitialisationProcessus


class MyTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_something(self):
        self.assertEqual(True, True)


class OrienteurTransactionTest(unittest.TestCase):

    def setUp(self):
        self._orienteur = OrienteurTransaction()
        self._message = None

    def test_chargement_liste_processus(self):
        self._orienteur.charger_liste_processus()
        self.assertGreater(len(self._orienteur.dict_libelle), 0, "Le dictionnaire de libelles est vide")

    def test_orienter_message_vide(self):
        try:
            self._orienteur.orienter_message({})
            self.fail("ErreurInitialisationProcessus aurait du etre lance")
        except ErreurInitialisationProcessus:
            pass
        except Exception:
            self.fail("ErreurInitialisationProcessus aurait du etre lance")

    def test_orienter_message_processus_connu(self):
        self._orienteur.dict_libelle = {"MGPProcessus.senseur.lecture": "Senseur.ConsignerLecture"}
        processus = self._orienteur.orienter_message({"libelle":"MGPProcessus.senseur.lecture"})
        self.assertEqual(processus, "MGPProcessus.Senseur.ConsignerLecture")

    def test_orienter_message_processus_inconnu(self):
        #self._orienteur.dict_libelle = {"senseur.lecture": "MGPProcessus.Senseur.ConsignerLecture"}
        try:
            processus = self._orienteur.orienter_message({"libelle":"MGPProcessus.senseur.lecture"})
            self.fail("ErreurInitialisationProcessus aurait du etre lance")
        except ErreurInitialisationProcessus:
            pass

if __name__ == '__main__':
    unittest.main()

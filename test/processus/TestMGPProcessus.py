import unittest
from millegrilles.processus.MGProcessus import MGPProcessusControleur, ErreurEtapeInconnue
from millegrilles.processus.ProcessusTest import TestOrienteur

class MGPProcessusTest(unittest.TestCase):

    def setUp(self):
        self._document_dao = DocumentDaoStub()
        self._message_dao = MessageDaoStub()
        self._controleur = MGPProcessusControleur()
        self._controleur._message_dao = self._message_dao
        self._controleur._document_dao = self._message_dao
        self._evenement = {'etape-suivante': 'initiale'}

    def test_init(self):
        self.assertTrue(True)

    def test_executer_methodeinitiale(self):
        processus = TestOrienteur(self._controleur, self._evenement)
        methode = processus._identifier_etape_courante()
        self.assertIsNotNone(methode)

        methode() # Executer la methode

        self.assertTrue(processus._initiale_executee)

    def test_executer_methode_none(self):
        del self._evenement['etape-suivante'] # Effacer l'element etape-suivante

        processus = TestOrienteur(self._controleur, self._evenement)
        try:
            methode = processus._identifier_etape_courante()
            self.fail("On attendait une erreur, etape inconnue")
        except ErreurEtapeInconnue as erreur:
            pass

    def test_executer_methodeinexistante(self):
        self._evenement['etape-suivante'] = 'existe_pas' # Mettre methode qui n'existe pas dans TestOrienteur

        processus = TestOrienteur(self._controleur, self._evenement)
        try:
            methode = processus._identifier_etape_courante()
            self.fail("On attendait une erreur, attribut (methode) inconnue")
        except AttributeError as erreur:
            pass

class MessageDaoStub():
    pass

class DocumentDaoStub():
    pass


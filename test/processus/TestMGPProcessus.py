import unittest
from millegrilles.processus.MGProcessus import MGPProcessusControleur, ErreurEtapeInconnue
from millegrilles.processus.ProcessusTest import TestOrienteur
from millegrilles import Constantes

class MGPProcessusTest(unittest.TestCase):

    def setUp(self):
        self._document_dao = DocumentDaoStub()
        self._message_dao = MessageDaoStub()
        self._controleur = MGPProcessusControleur()
        self._controleur._message_dao = self._message_dao
        self._controleur._document_dao = self._message_dao
        self._evenement = {
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS: 'ProcessusTest.TestOrienteur',
            Constantes.PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE: 'initiale',
        }

    def test_init(self):
        self.assertTrue(True)

    def test_identifier_classe(self):
        ''' Identifier une classe, la charger dynamiquement et creer une instance '''
        processus = self._controleur.identifier_processus(self._evenement)
        self.assertIsNotNone(processus)

        # Creer instance de la classe pour verifier son fonctionnement
        instance_processus = processus(self._controleur, self._evenement)
        instance_processus.initiale()
        self.assertTrue(instance_processus._initiale_executee)


    def test_executer_methodeinitiale(self):
        ''' Identifier l'etape, charger la methode dynamiquement et l'executer '''
        processus = TestOrienteur(self._controleur, self._evenement)
        methode = processus._identifier_etape_courante()
        self.assertIsNotNone(methode)

        methode() # Executer la methode

        self.assertTrue(processus._initiale_executee)

    def test_executer_methode_none(self):
        del self._evenement[Constantes.PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE] # Effacer l'element etape-suivante

        processus = TestOrienteur(self._controleur, self._evenement)
        try:
            methode = processus._identifier_etape_courante()
            self.fail("On attendait une erreur, etape inconnue")
        except ErreurEtapeInconnue as erreur:
            pass

    def test_executer_methodeinexistante(self):
        self._evenement[Constantes.PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE] = 'existe_pas' # Mettre methode qui n'existe pas dans TestOrienteur

        processus = TestOrienteur(self._controleur, self._evenement)
        try:
            methode = processus._identifier_etape_courante()
            self.fail("On attendait une erreur, attribut (methode) inconnue")
        except AttributeError as erreur:
            pass

    def test_transmettre_message_etape_suivante(self):
        processus = TestOrienteur(self._controleur, self._evenement)
        processus._document_processus = {
            Constantes.MONGO_DOC_ID: "dummy-doc-id"
        }

        processus._etape_complete = True
        processus._etape_suivante = 'finale'
        processus.transmettre_message_etape_suivante()

        params_transmis = self._controleur._message_dao.tranmettre_evenement_mgpprocessus_params
        self.assertIsNotNone(params_transmis)
        print('test_transmettre_message_etape_suivante, param transmis sur message: %s' % str(params_transmis))

class MessageDaoStub():

    def __init__(self):
        self.tranmettre_evenement_mgpprocessus_params = None

    def transmettre_evenement_mgpprocessus(self, id_document, nom_processus, nom_etape='initiale'):
        self.tranmettre_evenement_mgpprocessus_params = (id_document, nom_processus, nom_etape)

class DocumentDaoStub():
    pass


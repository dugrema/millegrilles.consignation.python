import unittest
from millegrilles.processus.OrienteurTransaction import OrienteurTransaction
from millegrilles.processus.OrienteurTransaction import ErreurInitialisationProcessus
from millegrilles import Constantes

class OrienteurTransactionTest(unittest.TestCase):

    def setUp(self):
        self._message_dao = MessageDAOStub()
        self._document_dao = DocumentDAOStub()
        self._orienteur = OrienteurTransaction()
        # Ajouter les DAOs stub
        self._orienteur._message_dao = self._message_dao
        self._orienteur._document_dao = self._document_dao
        self._message = None

    # ************* Section pour tester l'orientation ***************

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

    ''' Verifier qu'une erreur est lancee immediatement si le document de transaction n'existe pas. '''
    def test_orienter_message_document_inconnu(self):
        try:
            self._orienteur.orienter_message({Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: "dummy_object_id_string"})
            self.fail("ErreurInitialisationProcessus aurait du etre lance")
        except ErreurInitialisationProcessus:
            self.assertTrue(self._document_dao._called_charger_document_par_id,
                            "Le chargement du document aurait du etre invoque.")
            pass
        except Exception:
            print(Exception, e)
            self.fail("ErreurInitialisationProcessus aurait du etre lance")

    def test_orienter_message_processus_inconnu(self):
        self._document_dao._document = {Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION:
                                            {Constantes.TRANSACTION_MESSAGE_LIBELLE_INDICE_PROCESSUS: "senseur.lecture"}}
        try:
            processus = self._orienteur.orienter_message({Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: "dummy_object_id_string"})
            self.fail("ErreurInitialisationProcessus aurait du etre lance")
        except ErreurInitialisationProcessus:
            self.assertTrue(self._document_dao._called_charger_document_par_id,
                            "Le chargement du document aurait du etre invoque.")
            pass
        except Exception:
            print(Exception, e)
            self.fail("ErreurInitialisationProcessus aurait du etre lance")

    def test_orienter_message_typeprocessus_inconnu(self):
        self._document_dao._document = {"charge-utile": {"libelle-transaction": "MGJS.senseur.lecture"}}
        try:
            processus = self._orienteur.orienter_message({Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: "dummy_object_id_string"})
            self.fail("ErreurInitialisationProcessus aurait du etre lance")
        except ErreurInitialisationProcessus:
            self.assertTrue(self._document_dao._called_charger_document_par_id,
                            "Le chargement du document aurait du etre invoque.")
            pass
        except Exception as e:
            print(Exception, e)
            self.fail("ErreurInitialisationProcessus aurait du etre lance, erreur: %s" % str(e))

    def test_orienter_message_processus_connu(self):
        self._document_dao._document = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION: {
                Constantes.TRANSACTION_MESSAGE_LIBELLE_INDICE_PROCESSUS: "MGPProcessus.senseur.lecture"
            }
        }
        self._orienteur.dict_libelle = {"MGPProcessus.senseur.lecture": "Senseur.ConsignerLecture"}
        #{"libelle": "MGPProcessus.senseur.lecture"}
        processus = self._orienteur.orienter_message({Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: "dummy_object_id_string"})
        self.assertEqual(processus, ("MGPProcessus", "senseur.lecture"))


    # ************* Section pour tester le callback ***************
    def test_extraire_evenement(self):

        evenement_dict = self._orienteur.extraire_evenement(b'{"label":"value"}')
        self.assertEqual(evenement_dict["label"], "value")

class MessageDAOStub:

    def __init__(self):
        pass

class DocumentDAOStub:

    def __init__(self):
        self._document = None
        self._called_charger_document_par_id = False

    def charger_transaction_par_id(self, id_doc):
        self._called_charger_document_par_id = True
        return self._document


if __name__ == '__main__':
    unittest.main()

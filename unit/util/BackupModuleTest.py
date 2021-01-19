import datetime

from base64 import b64decode

from unit.helpers.TestBaseContexte import TestCaseContexte
from millegrilles import Constantes
from millegrilles.util.BackupModule import BackupUtil, HandlerBackupDomaine


class BackupUtilTest(TestCaseContexte):

    def setUp(self) -> None:
        self.backup_util = BackupUtil(self.contexte)

    def test_preparer_cipher(self):
        clecert = self.contexte.configuration.cle
        info_cles = {
            'certificat': [clecert.cert_bytes.decode('utf-8')],
            'certificat_millegrille': clecert.chaine[-1],
            'certificats_backup': dict(),
        }
        cipher, transaction_maitrecles = self.backup_util.preparer_cipher(dict(), info_cles)

        self.assertIsNotNone(cipher, "Cipher n'a pas ete genere")
        self.assertIsNotNone(cipher.iv, "IV pas inclus dans cipher")
        self.assertIsNotNone(cipher.password, "password pas inclus dans cipher")

        # Verifier presence du IV, cles
        self.assertIsNotNone(transaction_maitrecles.get('iv'), "IV absent de la transaction maitrecles")
        self.assertIsNotNone(transaction_maitrecles.get('cles'), "Cles chiffrees absentes de la transaction maitrecles")

        resultat = cipher.start_encrypt()
        resultat = resultat + cipher.update(b'test')
        resultat = resultat + cipher.finalize()
        self.assertIsNotNone(resultat, "Cipher n'est pas fonctionnel")
        self.assertEqual(32, len(resultat), "Erreur taille resultat cipher")

        self.__class__.logger.debug("Transaction maitrecles : %s" % transaction_maitrecles)

    def test_chiffrer_cle(self):
        clecert = self.contexte.configuration.cle
        certs_cles_backup = [
            clecert.cert_bytes.decode('utf-8'),
            clecert.chaine[-1]
        ]
        password = b'abcdefghijkl12345678910111213141'
        cles_chiffrees = self.backup_util.chiffrer_cle(certs_cles_backup, password)

        self.assertEqual(2, len(cles_chiffrees))

        # S'assurer que les cles sont formattes en base64 valide
        for cle in cles_chiffrees.values():
            resultat = b64decode(cle)


class HandlerBackupDomaineTest(TestCaseContexte):

    def setUp(self) -> None:
        self.handler = HandlerBackupDomaine(
            self.contexte, "TestDomaine", "TestTransactions", "TestDocuments",
            niveau_securite=Constantes.SECURITE_PROTEGE
        )

    def test_transmettre_evenement_backup(self):
        ts = datetime.datetime.utcnow()
        self.handler.transmettre_evenement_backup('evenement_test', ts)

        # Stub generateur transaction, verifier message transmis
        generateur_transactions = self.contexte.generateur_transactions
        liste_messages = generateur_transactions.liste_emettre_message

        # S'assurer que l'evenement a ete emis
        self.assertEqual(1, len(liste_messages))

    def test_effectuer_requete_domaine(self):
        contexte = self.contexte
        document_dao = contexte.document_dao

        # Prep data
        ts = datetime.datetime.utcnow()
        contexte.document_dao.valeurs_aggregate.append('dummy')

        # Call methode a tester
        resultat_aggregate = self.handler._effectuer_requete_domaine(ts)

        # Verification
        self.assertEqual('dummy', resultat_aggregate)
        call_aggregate = document_dao.calls_aggregate[0]
        requete_match = call_aggregate['args'][0][0]['$match']
        self.assertEqual(ts, requete_match['_evenements.transaction_traitee']['$lt'])

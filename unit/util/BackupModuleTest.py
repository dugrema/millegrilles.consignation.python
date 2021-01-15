from unit.helpers.TestBaseContexte import TestCaseContexte

from millegrilles.util.BackupModule import BackupUtil


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

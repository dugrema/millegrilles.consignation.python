from millegrilles.SecuritePKI import VerificateurCertificats
from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles

import unittest
import logging


logging.basicConfig()
logging.getLogger('test').setLevel(logging.DEBUG)
logging.getLogger('millegrilles.SecuritePKI').setLevel(logging.DEBUG)


class TestVerificationChaine(unittest.TestCase):

    def setUp(self) -> None:
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser(init_document=False, init_message=False)

        self.verificateur = VerificateurCertificats(self.contexte)
        self.logger = logging.getLogger('test')

    def test_verifier_cert_1(self):
        """ Verification d'un certificat valide """
        enveloppe = self.verificateur.charger_certificat(fichier='./data/cert_1.pem')
        self.logger.debug('Cert_1 fingerprint: %s' % enveloppe.fingerprint_ascii)
        self.assertEqual('3eff5b5fcc8484ea9a3579b29ca0167339014694', enveloppe.fingerprint_ascii)
        resultat, output_txt = self.verificateur._verifier_chaine(enveloppe)
        self.logger.debug("Code %s, output: %s" % (str(resultat), output_txt))
        self.assertTrue(resultat)

    def test_verifier_cert_2(self):
        """ Verification d'un certificat avec chain incomplete """
        enveloppe = self.verificateur.charger_certificat(fichier='./data/cert_2_CAInvalid.pem')
        self.logger.debug('Cert_2 fingerprint: %s' % enveloppe.fingerprint_ascii)
        self.assertEqual('269d6cc53d1e87617c55e6e93b52f51476444a1e', enveloppe.fingerprint_ascii)
        resultat, output_txt = self.verificateur._verifier_chaine(enveloppe)
        self.logger.debug("Code %s, output: %s" % (str(resultat), output_txt))
        self.assertFalse(resultat)

    def test_verifier_cert_3(self):
        """ Verification d'un certificat CA=TRUE """
        enveloppe = self.verificateur.charger_certificat(fichier='./data/cert_3_intermediaire.pem')
        self.logger.debug('Cert_3 fingerprint: %s' % enveloppe.fingerprint_ascii)
        self.assertEqual('e2ff90cf369f6f03d0abe6c247c09a8143873361', enveloppe.fingerprint_ascii)
        resultat, output_txt = self.verificateur._verifier_chaine(enveloppe)
        self.logger.debug("Code %s, output: %s" % (str(resultat), output_txt))
        self.assertTrue(resultat)

    def test_verifier_cert_root(self):
        """ Verification du certificat CA (root) lui-meme """
        enveloppe = self.verificateur.charger_certificat(fichier='./data/cert_root.pem')
        self.logger.debug('Cert_4 fingerprint: %s' % enveloppe.fingerprint_ascii)
        self.assertEqual('42905255f627cdaac59d976aec8035082f76ffe9', enveloppe.fingerprint_ascii)
        resultat, output_txt = self.verificateur._verifier_chaine(enveloppe)
        self.logger.debug("Code %s, output: %s" % (str(resultat), output_txt))
        self.assertTrue(resultat)

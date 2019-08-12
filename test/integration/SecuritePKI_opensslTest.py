from millegrilles.SecuritePKI import VerificateurCertificats, CertificatInvalide
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

        self.contexte.configuration._pki_config[Constantes.CONFIG_MQ_CA_CERTS] = './data/cert_fullcachain.pem'

        self.verificateur = VerificateurCertificats(self.contexte)
        self.logger = logging.getLogger('test')

    def tearDown(self) -> None:
        self.verificateur.close()  # Nettoyer fichiers tmp

    def test_verifier_cert_1(self):
        """ Verification d'un certificat valide """
        enveloppe = self.verificateur.charger_certificat(fichier='./data/cert_1.pem')
        self.logger.debug('Cert_1 fingerprint: %s' % enveloppe.fingerprint_ascii)
        self.assertEqual('3eff5b5fcc8484ea9a3579b29ca0167339014694', enveloppe.fingerprint_ascii)
        self.assertTrue(enveloppe.est_verifie)

        resultat, output_txt = self.verificateur._verifier_chaine(enveloppe)
        self.logger.debug("Code %s, output: %s" % (str(resultat), output_txt))
        self.assertTrue(resultat)

    def test_verifier_cert_2(self):
        """ Verification d'un certificat avec chain incomplete """
        self.assertRaises(
            CertificatInvalide,
            self.verificateur.charger_certificat,
            fichier='./data/cert_2_CAInvalid.pem'
        )

    def test_verifier_cert_3(self):
        """ Verification d'un certificat CA=TRUE """
        enveloppe = self.verificateur.charger_certificat(fichier='./data/cert_3_intermediaire.pem')
        self.logger.debug('Cert_3 fingerprint: %s' % enveloppe.fingerprint_ascii)
        self.assertEqual('e2ff90cf369f6f03d0abe6c247c09a8143873361', enveloppe.fingerprint_ascii)
        self.assertTrue(enveloppe.est_verifie)

        resultat, output_txt = self.verificateur._verifier_chaine(enveloppe)
        self.logger.debug("Code %s, output: %s" % (str(resultat), output_txt))
        self.assertTrue(resultat)

    def test_verifier_cert_root(self):
        """ Verification du certificat CA (root) lui-meme """
        enveloppe = self.verificateur.charger_certificat(fichier='./data/cert_root.pem')
        self.logger.debug('Cert_4 fingerprint: %s' % enveloppe.fingerprint_ascii)
        self.assertEqual('42905255f627cdaac59d976aec8035082f76ffe9', enveloppe.fingerprint_ascii)
        self.assertTrue(enveloppe.est_verifie)

        resultat, output_txt = self.verificateur._verifier_chaine(enveloppe)
        self.logger.debug("Code %s, output: %s" % (str(resultat), output_txt))
        self.assertTrue(resultat)

    def test_verifier_untrusted(self):
        """ Verification du processus d'ajout untrusted """
        self.contexte.configuration._pki_config[Constantes.CONFIG_MQ_CA_CERTS] = Constantes.DEFAUT_CA_CERTS
        try:
            self.verificateur.charger_certificat(fichier='./data/cert_untrusted_1.pem')
        except CertificatInvalide as e:
            pass
        try:
            self.verificateur.charger_certificat(fichier='./data/cert_untrusted_2.pem')
        except CertificatInvalide as e:
            pass

        enveloppe = self.verificateur.charger_certificat(fichier='./data/cert_1.pem')
        self.logger.debug('Cert_1 fingerprint: %s' % enveloppe.fingerprint_ascii)
        self.assertEqual('3eff5b5fcc8484ea9a3579b29ca0167339014694', enveloppe.fingerprint_ascii)
        self.assertTrue(enveloppe.est_verifie)

        resultat, output_txt = self.verificateur._verifier_chaine(enveloppe)
        self.logger.debug("Code %s, output: %s" % (str(resultat), output_txt))
        self.assertTrue(resultat)

import logging

from unittest import TestCase

from millegrilles.util.Hachage import hacher, verifier_hachage, ErreurHachage, Hacheur, VerificateurHachage

# Setup logging
logging.basicConfig()
logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)
logging.getLogger('millegrilles').setLevel(logging.DEBUG)


class HacherTest(TestCase):

    VALEUR_1 = 'allo'
    VALEUR_1_BYTES = b'allo'
    HACHAGE_VALEUR_1 = 'z8Vv8e3sDPugPF1NNhssx3qBCKr8PHEBHfUmeSHb9GJz4NP3mHhthPgZYpNJnj8C5PDraUeBDDDoPbEyQgAYhfVoLYY'
    HACHAGE_VALEUR_1_SHA256 = 'zQmZJH8hPKTmyjwPTdBFd5Zf7nMBfyAba5sxUzdSS9Z1URp'

    def test_hacher_string(self):
        resultat = hacher(HacherTest.VALEUR_1)
        logger.debug("Resultat hacher_string: %s" % resultat)
        self.assertEqual(resultat, HacherTest.HACHAGE_VALEUR_1)

    def test_hacher_bytes(self):
        resultat = hacher(HacherTest.VALEUR_1_BYTES)
        logger.debug("Resultat hacher_string: %s" % resultat)
        self.assertEqual(resultat, HacherTest.HACHAGE_VALEUR_1)

    def test_verifier_string(self):
        verifier_hachage(HacherTest.HACHAGE_VALEUR_1, HacherTest.VALEUR_1)

    def test_verifier_string_mismatch(self):
        self.assertRaises(ErreurHachage, verifier_hachage, HacherTest.HACHAGE_VALEUR_1, 'mauvaise valeur')

    def test_hacher_string_classe(self):
        hacheur = Hacheur()
        hacheur.update(HacherTest.VALEUR_1)
        resultat = hacheur.finalize()
        self.assertEqual(resultat, HacherTest.HACHAGE_VALEUR_1)

    def test_hacher_bytes_classe(self):
        hacheur = Hacheur()
        hacheur.update(HacherTest.VALEUR_1_BYTES)
        resultat = hacheur.finalize()
        self.assertEqual(resultat, HacherTest.HACHAGE_VALEUR_1)

    def test_hacher_string_sha256(self):
        resultat = hacher(HacherTest.VALEUR_1, 'sha2-256')
        logger.debug("Resultat test_hacher_string_sha256: %s" % resultat)
        self.assertEqual(resultat, HacherTest.HACHAGE_VALEUR_1_SHA256)

    def test_hacher_bytes_sha256(self):
        resultat = hacher(HacherTest.VALEUR_1_BYTES, 'sha2-256')
        logger.debug("Resultat test_hacher_bytes_sha256: %s" % resultat)
        self.assertEqual(resultat, HacherTest.HACHAGE_VALEUR_1_SHA256)

    def test_verifier_string_classe(self):
        verificateur = VerificateurHachage(HacherTest.HACHAGE_VALEUR_1)
        verificateur.update(HacherTest.VALEUR_1)
        verificateur.verify()

    def test_verifier_string_classe_mismatch(self):
        verificateur = VerificateurHachage(HacherTest.HACHAGE_VALEUR_1)
        verificateur.update('Valeur incorrecte')
        self.assertRaises(ErreurHachage, verificateur.verify)

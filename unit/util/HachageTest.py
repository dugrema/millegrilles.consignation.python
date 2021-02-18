import logging

from unittest import TestCase

from millegrilles.util.Hachage import hacher, verifier_hachage, ErreurHachage

# Setup logging
logging.basicConfig()
logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)
logging.getLogger('millegrilles').setLevel(logging.DEBUG)


class HacherTest(TestCase):

    VALEUR_1 = 'allo'
    VALEUR_1_BYTES = b'allo'
    HACHAGE_VALEUR_1 = 'z8Vv8e3sDPugPF1NNhssx3qBCKr8PHEBHfUmeSHb9GJz4NP3mHhthPgZYpNJnj8C5PDraUeBDDDoPbEyQgAYhfVoLYY'

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

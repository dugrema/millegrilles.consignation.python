import logging
import multibase

from cryptography.exceptions import InvalidTag
from unittest import TestCase
from base64 import b64encode, b64decode

from millegrilles.util.Chiffrage import CipherMsg2Chiffrer, CipherMsg2Dechiffrer
from millegrilles.util.Hachage import verifier_hachage


# Setup logging
logging.basicConfig()
logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)
logging.getLogger('millegrilles').setLevel(logging.DEBUG)


MESSAGE_1 = 'contenu a chiffrer'
MESSAGE_1_CHIFFRE = {
    'ciphertext': b'fDWm5jZoBbF/+4awTYNCFuYZ',
    'password': b'in38+aou4BwZ0v5CEtSkCJZnwoN3WjI11IfQNfVDWxs=',
    'meta': {
        'iv': 'm/hohj48Ala84SFrB',
        'hachage_bytes': 'mE0D3QN71zbjnSV51xYY/JrYQEV+DYbGSxaxfb+oDolFgWJ987iNXqKvY3jPNIbv1ycm8jmnke5Ps1wMXBKi0dc/j',
        'tag': 'mV0zERwOcu7dwFSE6YfSNVA'
    }
}


class ChiffrageTest(TestCase):

    def test_chiffrer_string(self):
        cipher = CipherMsg2Chiffrer()
        valeur_init = cipher.start_encrypt()

        ciphertext = valeur_init + cipher.update(MESSAGE_1.encode('utf-8'))
        ciphertext = ciphertext + cipher.finalize()

        logger.debug("Ciphertext : %s" % ciphertext)
        self.assertEqual(len(MESSAGE_1), len(ciphertext))
        self.assertEqual(16, len(cipher.tag))
        self.assertEqual(12, len(cipher.iv))
        self.assertEqual(32, len(cipher.password))

        meta = cipher.get_meta()
        logger.debug("Meta info : %s", meta)
        self.assertIsNotNone(meta['iv'])
        self.assertIsNotNone(meta['tag'])
        self.assertIsNotNone(meta['hachage_bytes'])

        # Pour alimenter test dechiffrage
        logger.debug("Ciphertext : %s" % b64encode(ciphertext))
        logger.debug("Secret key : %s" % b64encode(cipher.password))

    def test_dechiffrer_string(self):
        ciphertext_bytes = b64decode(MESSAGE_1_CHIFFRE['ciphertext'])
        password_bytes = b64decode(MESSAGE_1_CHIFFRE['password'])
        iv = MESSAGE_1_CHIFFRE['meta']['iv']
        tag = MESSAGE_1_CHIFFRE['meta']['tag']

        decipher = CipherMsg2Dechiffrer(iv, password_bytes, tag)
        resultat = decipher.update(ciphertext_bytes)
        resultat = resultat + decipher.finalize()
        resultat = resultat.decode('utf-8')

        logger.debug("Resultat dechiffrage : %s" % resultat)
        self.assertEqual(MESSAGE_1, resultat)

    def test_verifier_hachage_chiffre(self):
        hachage = MESSAGE_1_CHIFFRE['meta']['hachage_bytes']
        ciphertext = b64decode(MESSAGE_1_CHIFFRE['ciphertext'])
        verifier_hachage(hachage, ciphertext)

    def test_tag_invalide(self):
        ciphertext_bytes = b64decode(MESSAGE_1_CHIFFRE['ciphertext'])
        password_bytes = b64decode(MESSAGE_1_CHIFFRE['password'])
        iv = MESSAGE_1_CHIFFRE['meta']['iv']

        # Utiliser un mauvais tag
        tag = 'mBMTTc7yVJOOZhAL0NAOodA'

        decipher = CipherMsg2Dechiffrer(iv, password_bytes, tag)
        decipher.update(ciphertext_bytes)

        self.assertRaises(InvalidTag, decipher.finalize)

    def test_iv_invalide(self):
        ciphertext_bytes = b64decode(MESSAGE_1_CHIFFRE['ciphertext'])
        password_bytes = b64decode(MESSAGE_1_CHIFFRE['password'])
        tag = MESSAGE_1_CHIFFRE['meta']['tag']

        # Utiliser un mauvais IV
        iv = 'msIfE+yBRc9tuYYaj'

        decipher = CipherMsg2Dechiffrer(iv, password_bytes, tag)
        decipher.update(ciphertext_bytes)

        self.assertRaises(InvalidTag, decipher.finalize)

    def test_cycle(self):
        cipher = CipherMsg2Chiffrer()
        valeur_init = cipher.start_encrypt()
        ciphertext = valeur_init + cipher.update(MESSAGE_1.encode('utf-8'))
        ciphertext = ciphertext + cipher.finalize()
        meta = cipher.get_meta()

        decipher = CipherMsg2Dechiffrer(meta['iv'], cipher.password, meta['tag'])
        resultat = decipher.update(ciphertext)
        resultat = resultat + decipher.finalize()
        resultat = resultat.decode('utf-8')

        # Confirmer que le message est identique
        self.assertEqual(MESSAGE_1, resultat, 'Erreur comparaison message')

        # Confirmer que le hachage a fonctionne
        verifier_hachage(meta['hachage_bytes'], ciphertext)

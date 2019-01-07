import logging
import json
import binascii
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.exceptions import InvalidSignature

class SignateurTest:

    CERT_FOLDER = '/home/mathieu/certificates/millegrilles'

    def __init__(self):
        self.cle = None
        self._logger = logging.getLogger(self.__class__.__name__)
        self.signature = None

        self._hash_function = hashes.SHA512

    def load_cle(self):
        with open('%s/privkeys/dev1.pem' % SignateurTest.CERT_FOLDER, 'rb') as key_file:
            cle = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            self.cle = cle
            self._logger.debug("Cle privee chargee")

    def signer_json(self, dict_message):
        self.signature = self._produire_signature(dict_message)

    def _produire_signature(self, dict_message):
        message_json = json.dumps(dict_message, sort_keys=True)
        message_bytes = bytes(message_json, 'utf-8')
        self._logger.debug("Message en format json: %s" % message_json)

        signature = self.cle.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(self._hash_function()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self._hash_function()
        )

        signature_texte_utf8 = str(base64.b64encode(signature), 'utf-8')
        self._logger.debug("Signatures: %s" % signature_texte_utf8)

        return signature_texte_utf8


class Verificateur:

    def __init__(self):
        self.certificat = None
        self._logger = logging.getLogger(self.__class__.__name__)
        self._hash_function = hashes.SHA512

    def load_certificat(self):
        with open('%s/certs/dev1.cert.pem' % SignateurTest.CERT_FOLDER, 'rb') as key_file:
            certificat = x509.load_pem_x509_certificate(
                key_file.read(),
                backend=default_backend()
            )
            self.certificat = certificat
            self._logger.debug("Certificat charge: %s" % str(certificat))

    def verifier_signature(self, dict_message, signature):
        signature_bytes = base64.b64decode(signature)
        message_json = json.dumps(dict_message, sort_keys=True)
        message_bytes = bytes(message_json, 'utf-8')

        cle_publique = self.certificat.public_key()
        try:
            cle_publique.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(self._hash_function()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                self._hash_function()
            )
        except InvalidSignature:
            self._logger.exception("Signature invalide")

        self._logger.debug('Verification completee')


def test():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('SignateurTest').setLevel(logging.DEBUG)
    logging.getLogger('Verificateur').setLevel(logging.DEBUG)

    signateur = SignateurTest()
    signateur.load_cle()
    message = {'cle': 'valeur', 'nombre': 24}
    signateur.signer_json(message)

    verificateur = Verificateur()
    verificateur.load_certificat()
    verificateur.verifier_signature(message, signateur.signature)


# Main
test()
# Module qui sert a aligner les algorithmes de cryptage Python et Javascript
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from cryptography import x509
from base64 import b64encode, b64decode

import logging
import datetime
import os
import re
import binascii

class JavascriptPythonAsymetric:

    def __init__(self):
        self._logger = logging.getLogger('%s' % self.__class__.__name__)
        self.fichier_cle = '/opt/millegrilles/dev2/pki/keys/dev2_middleware.key.pem'
        self.fichier_cert = '/opt/millegrilles/dev2/pki/certs/dev2_middleware.cert.pem'
        self.cert = None
        self.private = None

        self.charger_cles()

    def charger_cles(self):
        with open(self.fichier_cle, "rb") as keyfile:
            cle = serialization.load_pem_private_key(
                keyfile.read(),
                password=None,
                backend=default_backend()
            )
            self.private = cle

        self._logger.info("Cle courante: %s" % str(self.private))

        with open(self.fichier_cert, 'rb') as certificat_pem:
            certificat_courant_pem = certificat_pem.read()
            # certificat_pem = bytes(certificat_pem, 'utf-8')
            cert = x509.load_pem_x509_certificate(
                certificat_courant_pem,
                backend=default_backend()
            )
            self.cert = cert

        self._logger.info("Certificat courant: %s" % str(self.cert))

    def decrypter_contenu(self, contenu):
        self._logger.info('------- JavascriptPythonAsymetric.decrypter_contenu() ----------')
        """
        Utilise la cle privee en memoire pour decrypter le contenu.
        :param contenu:
        :return:
        """
        contenu_bytes = b64decode(contenu)
        self._logger.info("Contenu bytes (%d): %s" % (len(contenu_bytes), binascii.hexlify(contenu_bytes)))

        contenu_decrypte = self.private.decrypt(
            contenu_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return contenu_decrypte

    def crypter_contenu(self, message):
        self._logger.info('------- JavascriptPythonAsymetric.crypter_contenu() ----------')
        cle_secrete_backup = self.cert.public_key().encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return cle_secrete_backup


    def executer(self):

        contenu = 'v2oS1YZsX7+aCWfzf0DQtsmlSDrR/YuuFIUxiuwJIz6kXGHI8S9OBs0w1dw/oJvcHDWlcNcNDIENs9mtaSRnNgQQgD+x12dFHxsGL8kWiW0QNGugFVMf9J/8fcfkVXUibbsKK/QwkEfdiBO+rN4yX1aXWqm35V0hL9FEDVUlb/JDJ+2l9sNvutw+1D5paFWOI+fYEzKae/29gW2O4QILw0wvF7deZc6LjU4LoG4kXkNlDGL+RwPK17OuXU6zrRf5ZBKE+CiUFvpRUqttCv7kC3shvQ6JSVI8c4J5hgSNWL6fpx9WJFaPEu+ItK5TF6GIZ/x4Tjxbwf1lP1Wah/bFRg=='
        resultat = self.decrypter_contenu(contenu)
        self._logger.info("Decrypter, Resultat est:  %s" % resultat)

        secret = b'Mon mot de passe, ce serait un secret. Je dis!'
        secret_crypte = self.crypter_contenu(secret)
        self._logger.info("Crypter: %s" % b64encode(secret_crypte).decode('utf-8'))


class JavascriptPythonSymmetric:

    def __init__(self):
        self._logger = logging.getLogger('%s' % self.__class__.__name__)

    def decrypter_contenu(self, key, iv, contenu):
        self._logger.info('------- JavascriptPythonSymmetric.decrypter_contenu() ----------')
        keyb = b64decode(key)
        ivb = b64decode(iv)
        contenub = b64decode(contenu)
        cipher = Cipher(algorithms.AES(keyb), modes.CBC(ivb), backend=default_backend())
        decryptor = cipher.decryptor()

        resultat = decryptor.update(contenub) + decryptor.finalize()
        self._logger.info("Message decrypte (%d):\n%s" % (len(resultat), binascii.hexlify(resultat)))

        # On utilise AES 256, blocks de taille 256 bits.
        unpadder = PKCS7(256).unpadder()
        resultat_unpadded = unpadder.update(resultat) + unpadder.finalize()
        self._logger.info("Message unpadded (%d):\n%s" % (len(resultat_unpadded), binascii.hexlify(resultat_unpadded)))

        with open('/home/mathieu/output.tar.gz', 'wb') as output:
            output.write(resultat_unpadded)

    def executer(self):
        self.decrypter_contenu(
            key='AxuAY0oDJIh0bVLayHTp2uy2KPqj7Fx7PZhNqt9ZVxE=',
            iv='/9W0JEbFziynzG4xYl+GTw==',
            contenu='ScLql5g+y4T1JeyzfFV7z72kw4v7ZKMTANjPERC1aP8cSG6s/1hTuxQgenx3p2DJy7AFvJbGj5E9mBUJydQpaClOYwjU0NIWs13HSidtWjmcUDFCRYAaInPgC8nQYuIseiqMjEUkSEXL8cF/oqXppabI9noTeYQdA0zg4fHRXPJ905J54T7R9qQjkIyUg4WpfRx3buig0aoJ2CCdF/p9MPrq/r7bHz2fHOIlHNLrCrkqlyYMWxlcD3eL+SsBk6gM'
        )


# ---- MAIN ----
logging.basicConfig(level=logging.WARN)
logging.getLogger('JavascriptPythonAsymetric').setLevel(logging.DEBUG)
logging.getLogger('JavascriptPythonSymmetric').setLevel(logging.DEBUG)

asymetric = JavascriptPythonAsymetric()
asymetric.executer()

symetric = JavascriptPythonSymmetric()
symetric.executer()
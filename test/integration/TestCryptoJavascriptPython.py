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
        self.fichier_cle = '/opt/millegrilles/dev3/pki/deployeur/deployeur.key.pem'
        self.fichier_cert = '/opt/millegrilles/dev3/pki/deployeur/deployeur.cert.pem'
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

    def afficher_cle_publique(self):
        cle_publique_base64 = self.cert.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        cle_publique_base64 = cle_publique_base64\
            .replace('-----BEGIN PUBLIC KEY-----', '')\
            .replace('-----END PUBLIC KEY-----', '')\
            .replace('\n', '')
        self._logger.info("Cle publique:\n%s" % cle_publique_base64)

    def decrypter_contenu(self, contenu):
        """
        Utilise la cle privee en memoire pour decrypter le contenu.
        :param contenu:
        :return:
        """
        self._logger.info('------- JavascriptPythonAsymetric.decrypter_contenu() ----------')
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

        contenu = 'nin4VhwdVN9xs3UU/gUU7EC/Zgy/FXkaQdfmZn5Pr/u06okDJyXpkpxApZhQUj4dfG6OhAWbNEdCkMy3fuS0yREixaYnXaM0S9bSYW5SwFZ02ZkUm5BLOH//+MhVcIkos9mh9/EeJI+RGomZynHcoKkgnazy22g7FzlakiKHNgNegRHkvI4znv49geKnwEQkNjzLESLCqSW75CqSBwJyO/h6RfeOgRGILoohA6/8Mgm1iC4HRzuniftoslmRI4G0tpb/uiIrAT0NFGk7Nr8wJTg2TpfFEVHhmM/GWfBEB6T2Ce6n2ErmxBVfHOoeI4Ii8INi8rWdMo418JtGcOED4Q=='

        resultat = self.decrypter_contenu(contenu)
        self._logger.info("Decrypter, Resultat est:  %s" % resultat)
        self._logger.info("UTf-8:  %s" % b64encode(resultat).decode('utf-8'))

        # secret = b'Mon mot de passe, ce serait un secret. Je dis!'
        # secret_crypte = self.crypter_contenu(secret)
        # self._logger.info("Crypter: %s" % b64encode(secret_crypte).decode('utf-8'))


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
        unpadder = PKCS7(128).unpadder()
        resultat_unpadded = unpadder.update(resultat) + unpadder.finalize()
        self._logger.info("Message unpadded (%d):\n%s" % (len(resultat_unpadded), binascii.hexlify(resultat_unpadded)))

        resultat_string = resultat_unpadded.decode('utf-8')
        self._logger.info("Message string: %s" % resultat_string)

        # with open('/home/mathieu/output.tar.gz', 'wb') as output:
        #    output.write(resultat_unpadded)

    def decrypter_fichier(self, nom_fichier, secret, iv):
        """
        Utilise la cle privee en memoire pour decrypter le contenu.
        :param contenu:
        :return:
        """
        self._logger.info('------- JavascriptPythonSymetric.decrypter_fichier() ----------')
        keyb = b64decode(secret)
        ivb = b64decode(iv)

        with open('/tmp/dict_encrypt/%s' % nom_fichier, 'rb') as fichier:
            contenub = fichier.read()

        cipher = Cipher(algorithms.AES(keyb), modes.CBC(ivb), backend=default_backend())
        decryptor = cipher.decryptor()

        resultat = decryptor.update(contenub) + decryptor.finalize()
        # self._logger.info("Message decrypte (%d)" % len(resultat))

        # On utilise AES 256, blocks de taille 256 bits.
        unpadder = PKCS7(128).unpadder()
        resultat_unpadded = unpadder.update(resultat) + unpadder.finalize()
        # self._logger.info("Message unpadded (%d):\n%s" % (len(resultat_unpadded), binascii.hexlify(resultat_unpadded)))

        # resultat_string = resultat_unpadded.decode('utf-8')
        # self._logger.info("Message string: %s" % resultat_string)

        with open('/tmp/dict_encrypt/decrypt/%s' % nom_fichier, 'wb') as output:
            output.write(resultat_unpadded)

    def executer(self):
        self.decrypter_fichier(
            nom_fichier='VID_20190824_172006.mp4',
            secret='JcK1+LfeXzvXurj+I+LzNuizH4c8VGP75kgsWZiFiNk=',
            iv='J7V9EHqgDJ8r3Gp3zJWO0g=='
        )


# ---- MAIN ----
logging.basicConfig(level=logging.WARN)
logging.getLogger('JavascriptPythonAsymetric').setLevel(logging.DEBUG)
logging.getLogger('JavascriptPythonSymmetric').setLevel(logging.DEBUG)

# asymetric = JavascriptPythonAsymetric()
# asymetric.afficher_cle_publique()
# asymetric.executer()

symetric = JavascriptPythonSymmetric()
symetric.executer()
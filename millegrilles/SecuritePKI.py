# Module pour la securite avec certificats (PKI)
import logging
import json
import re
import base64
import binascii
import datetime
import uuid
import getpass
import socket
import subprocess
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.name import NameOID


class SignateurTransaction:
    """ Signe une transaction avec le certificat du noeud. """

    def __init__(self):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def charger_certificat(self):
        pass

    def _charger_cle_privee(self):
        pass


class VerificateurTransaction:
    """ Verifie la signature des transactions. """

    def __init__(self):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def charger_certificat(self):
        pass


class VerificateurCertificats:
    """
    Verifie les certificats en utilisant les certificats CA et openssl.

    Charge les certificats en utilisant le fingerprint (inclu dans les transactions). Si un certificat n'est pas
    connu, le verificateur va tenter de le trouver dans MongoDB. Si le certificat n'existe pas dans Mongo,
    une erreur est lancee via RabbitMQ pour tenter de trouver le certificat via un des noeuds.
    """

    def __init__(self, contexte):
        self._contexte = contexte
        self._cache_certificats = dict()

    def verifier_certificat(self, fingerprint):
        certificat = self._charger_certificat(fingerprint)

        # Valider le certificat
        self._cache_certificats[fingerprint] = EnveloppeCertificat(fingerprint, certificat)

    def _charger_certificat(self, fingerprint):
        certificat = self._cache_certificats.get(fingerprint)

        if certificat is None:
            # Tenter de charger a partir d'une copie locale
            fichier = '%s' % fingerprint
            if os.path.isfile(fichier):
                with open(fichier, "rb") as certfile:
                    certificat = x509.load_pem_x509_certificate(
                        certfile.read(),
                        backend=default_backend()
                    )

            if certificat is None:
                # Tenter de charger a partir de MongoDB.
                pass

                if certificat is None:
                    raise CertificatInconnu("Certificat inconnu: %s" % fingerprint)

        return certificat


class EnveloppeCertificat:
    """ Encapsule un certificat. """

    def __init__(self, fingerprint, certificat):
        """
        :param fingerprint: Fingerprint en binascii (lowercase, pas de :) du certificat
        """

        self._fingerprint = fingerprint
        self._certificat = certificat
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._repertoire_certificats = None

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def certificat(self):
        return self._certificat


class CertificatInconnu(Exception):
    def __init__(self, message, errors):
        super().init(message)
        self.errors = errors

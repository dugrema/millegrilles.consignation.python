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

from millegrilles import Constantes


class SignateurTransaction:
    """ Signe une transaction avec le certificat du noeud. """

    def __init__(self, configuration):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.configuration = configuration
        self._hash_function = hashes.SHA512

        self.certificat = None
        self._cle = None
        self.enveloppe = None

    def initialiser(self):
        self._charger_cle_privee()
        self._charger_certificat()

        # Verifier que le certificat peut bien etre utilise pour signer des transactions
        self._verifier_usage()

        self.enveloppe = EnveloppeCertificat(self.certificat)

    def _verifier_certificat(self, dict_message):
        # self._verifier_usage()  # Deja fait au chargement
        self._verifier_cn(dict_message)

    def _verifier_usage(self):
        # S'assurer que ce certificat set bien a signer
        basic_constraints = self.certificat.extensions.get_extension_for_class(x509.BasicConstraints)
        self._logger.debug("Basic Constraints: %s" % str(basic_constraints))
        key_usage = self.certificat.extensions.get_extension_for_class(x509.KeyUsage).value
        self._logger.debug("Key usage: %s" % str(key_usage))

        supporte_signature_numerique = key_usage.digital_signature
        if not supporte_signature_numerique:
            raise Exception('Le certificat ne supporte pas les signatures numeriques')

    def _verifier_cn(self, dict_message):
        sujet = self.certificat.subject
        self._logger.debug('Sujet du certificat')
        for elem in sujet:
            self._logger.debug("%s" % str(elem))

        cn = sujet.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self._logger.debug("Common Name: %s" % cn)

        message_noeud = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE].get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_SOURCE_SYSTEME)
        if message_noeud is not None and '@' in message_noeud:
            message_noeud = message_noeud.split('@')[1]

        resultat_comparaison = (cn == message_noeud)
        if not resultat_comparaison:
            raise Exception(
                "Erreur de certificat: le nom du noeud (%s) ne correspond pas au certificat utilise pour signer (%s)." %
                (message_noeud, cn)
            )

    def signer(self, dict_message):
        """
        Signe le message et retourne une nouvelle version. Ajout l'information pour le certificat.

        :param dict_message: Message a signer.
        :return: Nouvelle version du message, signee.
        """

        # Copier la base du message et l'en_tete puisqu'ils seront modifies
        dict_message_effectif = dict_message.copy()
        en_tete = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE].copy()
        dict_message_effectif[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE] = en_tete

        self._verifier_certificat(dict_message_effectif)  # Verifier que l'entete correspond au certificat

        # Ajouter information du certification dans l'en_tete
        fingerprint_cert = self.enveloppe.fingerprint_ascii
        self._logger.debug("Fingerprint: %s" % fingerprint_cert)
        en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT] = fingerprint_cert

        signature = self._produire_signature(dict_message_effectif)
        dict_message_effectif[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE] = signature

        return dict_message_effectif

    def _produire_signature(self, dict_message):
        message_json = json.dumps(dict_message, sort_keys=True, separators=(',', ':'))
        message_bytes = bytes(message_json, 'utf-8')
        self._logger.debug("Message en format json: %s" % message_json)

        signature = self._cle.sign(
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

    def _charger_certificat(self):
        certfile_path = self.configuration.mq_certfile
        with open(certfile_path, "rb") as certfile:
            self.certificat = x509.load_pem_x509_certificate(
                certfile.read(),
                backend=default_backend()
            )

    def _charger_cle_privee(self):
        keyfile_path = self.configuration.mq_keyfile
        with open(keyfile_path, "rb") as keyfile:
            cle = serialization.load_pem_private_key(
                keyfile.read(),
                password=None,
                backend=default_backend()
            )
            self._cle = cle


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

    def __init__(self, certificat, fingerprint=None):
        """
        :param fingerprint: Fingerprint en binascii (lowercase, pas de :) du certificat
        """

        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._certificat = certificat
        self._repertoire_certificats = None

        if fingerprint is not None:
            self._fingerprint = fingerprint
        else:
            self._fingerprint = EnveloppeCertificat.calculer_fingerprint(certificat)

    @staticmethod
    def calculer_fingerprint(certificat):
        return certificat.fingerprint(hashes.SHA1())

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def fingerprint_ascii(self):
        return str(binascii.hexlify(self._fingerprint), 'utf-8')

    @property
    def certificat(self):
        return self._certificat


class CertificatInconnu(Exception):
    def __init__(self, message, errors):
        super().init(message)
        self.errors = errors

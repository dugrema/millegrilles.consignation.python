# Module pour la securite avec certificats (PKI)
import logging
import json
import re
import base64
import binascii
import getpass
import subprocess
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.name import NameOID

from millegrilles import Constantes


class UtilCertificats:

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

    def preparer_transaction_bytes(self, transaction_dict):
        """
        Prepare une transaction (dictionnaire) pour la signature ou la verification. Retourne des bytes.

        :param transaction_dict: Dictionnaire de la transaction a verifier.
        :return: Transaction nettoyee en bytes.
        """

        transaction_temp = transaction_dict.copy()
        regex_ignorer = re.compile('^_.+')
        keys = list()
        keys.extend(transaction_temp.keys())
        for cle in keys:
            m = regex_ignorer.match(cle)
            if m:
                del transaction_temp[cle]
                self._logger.debug("Enlever cle: %s" % cle)

        self._logger.debug("Message nettoye: %s" % str(transaction_temp))
        message_json = json.dumps(transaction_temp, sort_keys=True, separators=(',', ':'))
        message_bytes = bytes(message_json, 'utf-8')

        return message_bytes

    def verifier_certificat(self, dict_message):
        # self._verifier_usage()  # Deja fait au chargement
        self._verifier_cn(dict_message)

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

    # def _verifier_chaine_certificats(self):
    #     """ Verifie que la chaine de certicats remonte a un trusted CA """
        # trusted_ca_file = '/usr/local/etc/millegrilles/certs/millegrilles.RootCA.pem'
        # bundle_signing = '%s/pki.millegrilles.ssl.CAchain' % SignateurTest.CERT_FOLDER

        # Verifier si le certificat existe deja sur le disque
        # fingerprint_cert_bytes = self.certificat.fingerprint(hashes.SHA1())
        # fingerprint_cert = str(binascii.hexlify(fingerprint_cert_bytes), 'utf-8')

        # if not os.path.isdir(Verificateur.PATH_CERTIFICATS_TEMP):
        #     os.mkdir(Verificateur.PATH_CERTIFICATS_TEMP)
        # certificat_a_verifier = '%s/%s.pem' % (Verificateur.PATH_CERTIFICATS_TEMP, fingerprint_cert)
        # if not os.path.isfile(certificat_a_verifier):
        #     self._logger.debug("Fichier certificat va etre sauvegarde: %s" % fingerprint_cert)
        #     with open(certificat_a_verifier, "wb") as f:
        #         f.write(self.certificat.public_bytes(serialization.Encoding.PEM))

        # Utiliser openssl directement pour verifier la chaine de certification
        # resultat = subprocess.call([
        #     'openssl', 'verify',
        #     '-CAfile', trusted_ca_file,
        #     '-untrusted', bundle_signing,
        #     certificat_a_verifier
        # ])
        #
        # self._logger.debug("Resultat verification chaine certificat: %d" % resultat)
        #
        # if resultat == 2:
        #     raise Exception("Certificat invalide, la chaine est incomplete")
        # elif resultat != 0:
        #     raise Exception("Certificat invalide, code %d" % resultat)

class SignateurTransaction(UtilCertificats):
    """ Signe une transaction avec le certificat du noeud. """

    def __init__(self, configuration):
        super().__init__(configuration)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

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

        self.verifier_certificat(dict_message_effectif)  # Verifier que l'entete correspond au certificat

        # Ajouter information du certification dans l'en_tete
        fingerprint_cert = self.enveloppe.fingerprint_ascii
        self._logger.debug("Fingerprint: %s" % fingerprint_cert)
        en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT] = fingerprint_cert

        signature = self._produire_signature(dict_message_effectif)
        dict_message_effectif[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE] = signature

        return dict_message_effectif

    def _produire_signature(self, dict_message):
        message_bytes = self.preparer_transaction_bytes(dict_message)
        self._logger.debug("Message en format json: %s" % message_bytes)

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


class VerificateurTransaction(UtilCertificats):
    """ Verifie la signature des transactions. """

    def __init__(self, configuration):
        super().__init__(configuration)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def verifier(self, transaction):
        """
        Verifie la signature d'une transaction.

        :param transaction: Transaction str ou dict.
        :raises: InvalidSignature si la signature est invalide.
        :return: True si valide.
        """

        if transaction is str:
            dict_message = json.loads(transaction)
        elif transaction is dict:
            dict_message = transaction
        else:
            raise TypeError("La transaction doit etre en format str ou dict")

        signature = dict_message['_signature']

        if signature is None:
            raise ValueError("La _signature n'existe pas sur la transaction")

        regex_ignorer = re.compile('^_.+')
        keys = list()
        keys.extend(dict_message.keys())
        for cle in keys:
            m = regex_ignorer.match(cle)
            if m:
                del dict_message[cle]
                self._logger.debug("Enlever cle: %s" % cle)

        self._logger.debug("Message nettoye: %s" % str(dict_message))

        self._verifier_cn(dict_message)
        #self._verifier_chaine_certificats()
        self._verifier_signature(dict_message, signature)

        return True

    def _verifier_signature(self, dict_message, signature):
        """
        Verifie la signature du message avec le certificat.

        :param dict_message:
        :param signature:
        :raises InvalidSignature: Lorsque la signature est invalide
        :return:
        """
        signature_bytes = base64.b64decode(signature)
        message_json = json.dumps(dict_message, sort_keys=True, separators=(',', ':'))
        message_bytes = bytes(message_json, 'utf-8')
        self._logger.debug("Message pour verifier signature: %s" % str(message_json))

        cle_publique = self.certificat.public_key()
        cle_publique.verify(
            signature_bytes,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(self._hash_function()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self._hash_function()
        )
        self._logger.debug("Signature OK")

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

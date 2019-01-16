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


class PreparateurMessage:

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._identificateur_systeme = '%s@%s' % (getpass.getuser(), socket.getfqdn())

    def generer_entete(self, domaine):
        message_ref = {
            "en-tete": {
                "domaine": domaine,
                "estampille": int(datetime.datetime.utcnow().timestamp()),
                "noeud": self._identificateur_systeme,
                "uuid": str(uuid.uuid4()),
                "source-systeme": "test@dev2.maple.mdugre.info"
            }
        }

        return message_ref

class SignateurTest:

    CERT_FOLDER = '/usr/local/etc/millegrilles'

    def __init__(self):
        self.cle = None
        self.certificat = None
        self._logger = logging.getLogger(self.__class__.__name__)
        self.signature = None

        self._hash_function = hashes.SHA512

    def load_cle(self):
        with open('%s/pki.millegrilles.ssl.key' % SignateurTest.CERT_FOLDER, 'rb') as key_file:
            cle = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            self.cle = cle
            self._logger.debug("Cle privee chargee")

    def load_certificat(self):
        with open('%s/pki.millegrilles.ssl.cert' % SignateurTest.CERT_FOLDER, 'rb') as key_file:
            certificat = x509.load_pem_x509_certificate(
                key_file.read(),
                backend=default_backend()
            )
            self.certificat = certificat
            self._logger.debug("Certificat charge: %s" % str(certificat))

    def _verifier_certificat(self, dict_message):
        self._verifier_usage()
        self._verifier_cn(dict_message)

    def _verifier_usage(self):
        # S'assurer que ce certificat set bien a signer
        self._logger.debug("Certificat extensions: %s" % str(self.certificat.extensions))

        basic_constraints = self.certificat.extensions.get_extension_for_class(x509.BasicConstraints)
        self._logger.debug("Basic Constraints: %s" % str(basic_constraints))
        key_usage = self.certificat.extensions.get_extension_for_class(x509.KeyUsage).value
        self._logger.debug("Key usage: %s" % str(key_usage))
        subjectKeyIdentifier = self.certificat.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        authorityKeyIdentifier = self.certificat.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        self._logger.debug("Certificate Subject Key Identifier: %s" % subjectKeyIdentifier)
        self._logger.debug("Certificate issuer: %s" % binascii.hexlify(authorityKeyIdentifier.value.key_identifier))
        self._logger.debug("Subject key identifier: %s" % binascii.hexlify(subjectKeyIdentifier.value.digest))

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

        message_noeud = dict_message['en-tete'].get('noeud')
        if '@' in message_noeud:
            message_noeud = message_noeud.split('@')[1]

        resultat_comparaison = (cn == message_noeud)
        if not resultat_comparaison:
            raise Exception(
                "Erreur de certificat: le nom du noeud (%s) ne correspond pas au certificat utilise pour signer (%s)." %
                (message_noeud, cn)
            )

    def signer_json(self, dict_message):
        # Copier la base du message et l'en_tete puisqu'ils seront modifies
        dict_message_effectif = dict_message.copy()
        en_tete = dict_message['en-tete'].copy()
        dict_message_effectif['en-tete'] = en_tete

        self._verifier_certificat(dict_message_effectif)  # Verifier que l'entete correspond au certificat

        # Ajouter information du certification dans l'en_tete
        fingerprint_cert_bytes = self.certificat.fingerprint(hashes.SHA1())
        fingerprint_cert = str(binascii.hexlify(fingerprint_cert_bytes), 'utf-8')
        self._logger.debug("Fingerprint: %s" % str(fingerprint_cert))
        en_tete['certificat'] = fingerprint_cert

        self.signature = self._produire_signature(dict_message_effectif)
        dict_message_effectif['_signature'] = self.signature

        return dict_message_effectif

    def _produire_signature(self, dict_message):
        message_json = json.dumps(dict_message, sort_keys=True, separators=(',', ':'))
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

    PATH_CERTIFICATS_TEMP = '/usr/local/etc/millegrilles'

    def __init__(self):
        self.certificat = None
        self._logger = logging.getLogger(self.__class__.__name__)
        self._hash_function = hashes.SHA512

    def load_certificat(self):
        with open('%s/pki.millegrilles.ssl.cert' % SignateurTest.CERT_FOLDER, 'rb') as key_file:
            certificat = x509.load_pem_x509_certificate(
                key_file.read(),
                backend=default_backend()
            )
            self.certificat = certificat
            self._logger.debug("Certificat charge: %s" % str(certificat))

    def _verifier_chaine_certificats(self):
        """ Verifie que la chaine de certicats remonte a un trusted CA """
        trusted_ca_file = '/usr/local/etc/millegrilles/certs/millegrilles.RootCA.pem'
        bundle_signing = '%s/pki.millegrilles.ssl.CAchain' % SignateurTest.CERT_FOLDER

        # Verifier si le certificat existe deja sur le disque
        fingerprint_cert_bytes = self.certificat.fingerprint(hashes.SHA1())
        fingerprint_cert = str(binascii.hexlify(fingerprint_cert_bytes), 'utf-8')

        if not os.path.isdir(Verificateur.PATH_CERTIFICATS_TEMP):
            os.mkdir(Verificateur.PATH_CERTIFICATS_TEMP)
        certificat_a_verifier = '%s/%s.pem' % (Verificateur.PATH_CERTIFICATS_TEMP, fingerprint_cert)
        if not os.path.isfile(certificat_a_verifier):
            self._logger.debug("Fichier certificat va etre sauvegarde: %s" % fingerprint_cert)
#            with open(certificat_a_verifier, "wb") as f:
#                f.write(self.certificat.public_bytes(serialization.Encoding.PEM))

        # Utiliser openssl directement pour verifier la chaine de certification
        resultat = subprocess.call([
            'openssl', 'verify',
            '-CAfile', trusted_ca_file,
            '-untrusted', bundle_signing,
            certificat_a_verifier
        ])

        self._logger.debug("Resultat verification chaine certificat: %d" % resultat)

        if resultat == 2:
            raise Exception("Certificat invalide, la chaine est incomplete")
        elif resultat != 0:
            raise Exception("Certificat invalide, code %d" % resultat)


    def verifier_message(self, message):
        dict_message = json.loads(message)
        signature = dict_message['_signature']

        regex_ignorer = re.compile('^_.+')
        keys = list()
        keys.extend(dict_message.keys())
        for cle in keys:
            m = regex_ignorer.match(cle)
            if m:
                del dict_message[cle]
                self._logger.debug("Enlever cle: %s" % cle)

        self._logger.debug("Message nettoye: %s" % str(dict_message))

        self._verifier_sujet(dict_message)
        #self._verifier_chaine_certificats()
        self._verifier_signature(dict_message, signature)

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

    def _verifier_sujet(self, dict_message):
        sujet = self.certificat.subject
        self._logger.debug('Sujet du certificat')
        for elem in sujet:
            self._logger.debug("%s" % str(elem))

        cn = sujet.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self._logger.debug("Common Name: %s" % cn)

        message_noeud = dict_message['en-tete'].get('source-systeme')
        if message_noeud is not None and '@' in message_noeud:
            message_noeud = message_noeud.split('@')[1]

        resultat_comparaison = (cn == message_noeud)
        if not resultat_comparaison:
            raise Exception(
                "Erreur de certificat: le nom du noeud (%s) ne correspond pas au certificat utilise pour signer (%s)." %
                (message_noeud, cn)
            )

def test():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('test')
    logger.setLevel(logging.DEBUG)
    logging.getLogger('SignateurTest').setLevel(logging.DEBUG)
    logging.getLogger('Verificateur').setLevel(logging.DEBUG)

    preparateur = PreparateurMessage()
    message = preparateur.generer_entete('millegrilles.domaines.SenseursPassifs.lecture')
    message.update({
        'cle': 'valeur',
        'nombre': 24
    })

    signateur = SignateurTest()
    signateur.load_cle()
    signateur.load_certificat()
    message_maj = signateur.signer_json(message)

    message_maj_json = json.dumps(message_maj)
    logger.debug("Message signe: %s" % message_maj_json)

    verificateur = Verificateur()
    verificateur.load_certificat()
    verificateur.verifier_message(message_maj_json)
    # verificateur.verifier_signature(message_maj, signateur.signature)


def test_load_message():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('test')
    logging.getLogger('Verificateur').setLevel(logging.DEBUG)

    with open('/home/mathieu/message.json', 'r') as f:
        message = f.read()

    verificateur = Verificateur()
    verificateur.load_certificat()
    verificateur.verifier_message(message)


# Main
test()
#test_load_message()
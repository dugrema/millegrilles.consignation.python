# Module pour la securite avec certificats (PKI)
import logging
import json
import base64
import datetime
import pytz
import multibase
import multihash

from typing import Optional, Union
from cryptography.hazmat.primitives import serialization, asymmetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError
from multihash.constants import HASH_CODES

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesSecurityPki
from millegrilles.dao.MessageDAO import BaseCallback, CertificatInconnu, ExceptionConnectionFermee
from millegrilles.util.JSONMessageEncoders import DateFormatEncoder
from millegrilles.util.IdmgUtil import encoder_idmg_cert
from millegrilles.config.Autorisations import autorisations_idmg
from millegrilles.util.Hachage import hacher, map_code_to_hashes


class EnveloppeCertificat:
    """ Encapsule un certificat. """

    ENCODING_FINGERPRINT = 'base58btc'
    # HASH_FINGERPRINT = 'sha2-256'
    HASH_FINGERPRINT = 'blake2s-256'

    def __init__(self, certificat=None, certificat_pem=None, fingerprint=None):
        """
        :param fingerprint: Fingerprint en binascii (lowercase, pas de :) du certificat
        """

        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self.reste_chaine_pem: Optional[list] = None  # Certs CA de la chaine

        self._est_verifie = False  # Flag qui est change une fois la chaine verifiee

        if certificat_pem is not None:
            chaine_cert = None
            if isinstance(certificat_pem, str):
                chaine_cert = self.__split_chaine_certificats(certificat_pem)
            elif isinstance(certificat_pem, list):
                chaine_cert = certificat_pem

            if chaine_cert is not None:
                certificat_pem = bytes(chaine_cert[0], 'utf-8')
                self.reste_chaine_pem = chaine_cert[1:]

            self._certificat = x509.load_pem_x509_certificate(
                certificat_pem,
                backend=default_backend()
            )
        else:
            self._certificat = certificat
        self._repertoire_certificats = None

        if fingerprint is not None:
            self._fingerprint = fingerprint
        else:
            self._fingerprint = EnveloppeCertificat.calculer_fingerprint(self._certificat)

        self.__idmg: Optional[str] = None

    @staticmethod
    def calculer_fingerprint(certificat):
        hashing_code = HASH_CODES[EnveloppeCertificat.HASH_FINGERPRINT]
        hash_method = map_code_to_hashes(hashing_code)
        digest = certificat.fingerprint(hash_method)
        mh = multihash.encode(digest, EnveloppeCertificat.HASH_FINGERPRINT)
        mb = multibase.encode(EnveloppeCertificat.ENCODING_FINGERPRINT, mh)
        return mb.decode('utf-8')

    def __split_chaine_certificats(self, pem_str: str):
        chaine_certs = [c + UtilCertificats.END_CERTIFICATE for c in pem_str.split(UtilCertificats.END_CERTIFICATE)]
        return chaine_certs[0:-1]

    @property
    def fingerprint(self):
        if self._fingerprint is None:
            self._fingerprint = EnveloppeCertificat.calculer_fingerprint(self.certificat)
        return self._fingerprint

    @property
    def idmg(self) -> str:
        """
        Retourne le idmg du certificat.
        """
        if self.__idmg is None:
            self.__idmg = encoder_idmg_cert(self._certificat)
        return self.__idmg

    @property
    def certificat(self):
        return self._certificat

    @property
    def certificat_pem(self):
        return str(self.certificat.public_bytes(serialization.Encoding.PEM), 'utf-8')

    @property
    def public_key(self):
        public_key = self.certificat.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_str = str(public_key, 'utf-8')

        # # Enlever strings autour de la cle
        # public_key_str = public_key_str \
        #     .replace('-----BEGIN PUBLIC KEY-----', '') \
        #     .replace('-----END PUBLIC KEY-----', '') \
        #     .replace('\n', '')

        return public_key_str

    @property
    def get_roles(self):
        MQ_ROLES_OID = x509.ObjectIdentifier('1.2.3.4.1')
        extensions = self._certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_ROLES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_exchanges(self):
        MQ_EXCHANGES_OID = x509.ObjectIdentifier('1.2.3.4.0')
        extensions = self._certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_EXCHANGES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_domaines(self):
        MQ_DOMAINES_OID = x509.ObjectIdentifier('1.2.3.4.2')
        extensions = self._certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_DOMAINES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_user_id(self) -> str:
        MQ_USERID_OID = x509.ObjectIdentifier('1.2.3.4.3')
        extensions = self._certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_USERID_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        return oid_value

    @property
    def get_delegation_globale(self) -> str:
        MQ_DELEGATION_GLOBALE_OID = x509.ObjectIdentifier('1.2.3.4.4')
        extensions = self._certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_DELEGATION_GLOBALE_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        return oid_value

    @property
    def get_delegations_domaines(self) -> list:
        MQ_DOMAINES_OID = x509.ObjectIdentifier('1.2.3.4.5')
        extensions = self._certificat.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_DOMAINES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def subject_organization_name(self):
        organization = self._certificat.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if len(organization) > 0:
            return organization[0].value
        return None

    @property
    def subject_organizational_unit_name(self):
        org = self._certificat.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
        if org is not None and len(org) > 0:
            return org[0].value
        return None

    @property
    def subject_common_name(self):
        sujet = self.certificat.subject
        cn = sujet.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        return cn

    @property
    def not_valid_before(self) -> datetime.datetime:
        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        return pytz.utc.localize(self._certificat.not_valid_before)

    @property
    def not_valid_after(self) -> datetime.datetime:
        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        return pytz.utc.localize(self._certificat.not_valid_after)

    @property
    def subject_key_identifier(self):
        subjectKeyIdentifier = self.certificat.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        self._logger.debug("Certificate Subject Key Identifier: %s" % subjectKeyIdentifier)
        key_id = bytes.hex(subjectKeyIdentifier.value.digest)
        self._logger.debug("Subject key identifier: %s" % key_id)
        return key_id

    def subject_rfc4514_string(self):
        return self.certificat.subject.rfc4514_string()

    def subject_rfc4514_string_mq(self):
        """
        Subject avec ordre inverse pour RabbitMQ EXTERNAL
        :return:
        """
        subject = self.subject_rfc4514_string()
        subject_list = subject.split(',')
        subject_list.reverse()
        return ','.join(subject_list)

    @property
    def authority_key_identifier(self):
        authorityKeyIdentifier = self.certificat.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        key_id = bytes.hex(authorityKeyIdentifier.value.key_identifier)
        self._logger.debug("Certificate issuer: %s" % key_id)
        return key_id

    @property
    def is_rootCA(self):
        return self.is_CA and self.authority_key_identifier == self.subject_key_identifier

    @property
    def is_CA(self):
        basic_constraints = self.certificat.extensions.get_extension_for_class(x509.BasicConstraints)
        if basic_constraints is not None:
            return basic_constraints.value.ca
        return False

    @property
    def _is_valid_at_current_time(self):
        now = datetime.datetime.utcnow()

        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        try:
            is_valid_from = (now > pytz.utc.localize(self.certificat.not_valid_before))
            is_valid_to = (now < pytz.utc.localize(self.certificat.not_valid_after))
        except TypeError:
            is_valid_from = (now > self.certificat.not_valid_before)
            is_valid_to = (now < self.certificat.not_valid_after)

        return is_valid_from and is_valid_to

    def date_valide_concat(self):
        date_brute = self.certificat.not_valid_before
        date_formatte = date_brute.strftime('%Y%m%d%H%M%S')
        return date_formatte

    def date_valide(self):
        return self._is_valid_at_current_time

    @property
    def est_verifie(self):
        return self._est_verifie

    def set_est_verifie(self, flag):
        self._est_verifie = flag

    def formatter_subject(self):
        sujet_dict = {}

        sujet = self.certificat.subject
        for elem in sujet:
            self._logger.debug("%s" % str(elem))
            sujet_dict[elem.oid._name] = elem.value

        return sujet_dict

    def chiffrage_asymmetrique(self, cle_secrete):
        public_key = self.certificat.public_key()
        cle_secrete_backup = public_key.encrypt(
            cle_secrete,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        fingerprint = self.fingerprint
        return cle_secrete_backup, fingerprint

    def chaine_enveloppes(self):
        enveloppes = [self]
        for p in self.reste_chaine_pem:
            enveloppes.append(EnveloppeCertificat(certificat_pem=p))
        return enveloppes

    def chaine_pem(self):
        pems = [self.certificat_pem]
        pems.extend(self.reste_chaine_pem)
        return pems

    @property
    def fingerprint_cle_publique(self) -> str:
        pk = self.certificat.public_key()
        pem = pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        pem_bytes = ''.join(pem.strip().decode('utf-8').split('\n')[1:-1]).encode('utf-8')
        pk_bytes = base64.b64decode(pem_bytes)
        return hacher(pk_bytes, hashing_code='sha2-256', encoding='base64')

    def est_delegation_globale(self):
        """
        :return: True si le certificat est une delegation globale.
        """
        try:
            # Une delegation globale (proprietaire ou delegue) donne acces protege global
            delegation_globale = self.get_delegation_globale
            if delegation_globale in [Constantes.ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE, Constantes.ConstantesMaitreDesComptes.LIBVAL_DELEGUE]:
                return True
        except x509.extensions.ExtensionNotFound:
            pass  # OK

        return False

    def est_acces_protege(self, domaines: list = None) -> bool:
        """
        Permet de verifier si le certificat donne un acces protege.
        :param domaines: (Optionnel) Liste des domaines a verifier pour l'acces protege
        :return: True si exchange est 3.protege, 4.secure ou delegation_globale est proprietaire ou delegue.
        """
        try:
            # L'acces aux exchanges 3.protege ou 4.secure donne un acces protege global
            exchanges = self.get_exchanges
            if Constantes.SECURITE_PROTEGE in exchanges or Constantes.SECURITE_SECURE in exchanges:
                return True
        except x509.extensions.ExtensionNotFound:
            pass  # OK

        try:
            # Une delegation globale (proprietaire ou delegue) donne acces protege global
            delegation_globale = self.get_delegation_globale
            if delegation_globale in [Constantes.ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE, Constantes.ConstantesMaitreDesComptes.LIBVAL_DELEGUE]:
                return True
        except x509.extensions.ExtensionNotFound:
            pass  # OK

        try:
            # Verifier si l'usager a la delegation du domaine
            delegation_domaines = set(self.get_delegations_domaines)
            param_domaines = set(domaines)
            if len(delegation_domaines.intersection(param_domaines)) > 0:
                return True
        except x509.extensions.ExtensionNotFound:
            pass  # OK

        return False

    def est_acces_prive(self):
        """
        :return: True si le certificat permet un acces prive.
        """
        try:
            # Les roles 'prive' ou 'compte_prive' indiquent un certificat avec acces 2.prive
            roles = self.get_roles
            if Constantes.ConstantesGenerateurCertificat.ROLE_COMPTE_PRIVE in roles or \
                    Constantes.ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE in roles:
                return True
        except x509.extensions.ExtensionNotFound:
            pass  # OK

        # Le compte n'a pas le flag prive. On permet quand meme un acces prive si le certificat
        # a des indicateurs "proteges" globaux (pas de verification de domaines/sous-domaines)
        return self.est_acces_protege()


class UtilCertificats:

    END_CERTIFICATE = '-----END CERTIFICATE-----'

    def __init__(self, contexte):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._contexte = contexte
        self._sign_hash_function = hashes.SHA512
        self._contenu_hash_function = hashes.SHA256

        self._certificat: Optional[x509.Certificate] = None
        self._cle = None
        self._enveloppe: Optional[EnveloppeCertificat] = None
        self._chaine: Optional[list] = None

        # self.__validation_context: Optional[ValidationContext] = None
        self.__cert_millegrille: Optional[bytes] = None
        self.__autorisations_idmg: dict = autorisations_idmg()  # Autorisations pour idmg tierces

    def initialiser(self):
        # Charger le contexte de validation
        try:
            cle = self._contexte.configuration.cle
            self.__cert_millegrille = cle.chaine[-1].encode('utf-8')
        except:
            with open(self._contexte.configuration.mq_cafile, 'rb') as fichier:
                self.__cert_millegrille = fichier.read()

        self.__validation_context = ValidationContext(trust_roots=[self.__cert_millegrille])

        self._charger_cle_privee()
        self._charger_certificat()

        self._enveloppe = EnveloppeCertificat(certificat_pem='\n'.join(self._chaine))

        # Verifier que le certificat peut bien etre utilise pour signer des transactions
        # Valide aussi la chaine et les dates d'expiration
        # self.valider_x509_enveloppe(self._enveloppe)

    def preparer_transaction_bytes(self, transaction_dict):
        """
        Prepare une transaction (dictionnaire) pour la signature ou la verification. Retourne des bytes.

        :param transaction_dict: Dictionnaire de la transaction a verifier.
        :return: Transaction nettoyee en bytes.
        """

        # transaction_temp = dict()
        # for key, value in transaction_dict.items():
        #     if not key.startswith('_'):
        #         transaction_temp[key] = value
        #
        # # self._logger.debug("Message nettoye: %s" % str(transaction_temp))
        #
        # # Premiere passe, converti les dates. Les nombre floats sont incorrects.
        # message_json = json.dumps(
        #     transaction_temp,
        #     ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
        #     cls=DateFormatEncoder
        # )
        #
        # # HACK - Fix pour le decodage des float qui ne doivent pas finir par .0 (e.g. 100.0 doit etre 100)
        # message_json = json.loads(message_json, parse_float=self._parse_float)
        # message_json = json.dumps(
        #     message_json,
        #     ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
        #     sort_keys=True,
        #     separators=(',', ':')
        # )
        #
        # message_bytes = bytes(message_json, 'utf-8')
        #
        # return message_bytes

        return UtilCertificats.preparer_message_bytes(transaction_dict)

    @staticmethod
    def preparer_message_bytes(message: dict):
        """
                Prepare une transaction (dictionnaire) pour la signature ou la verification. Retourne des bytes.

                :param transaction_dict: Dictionnaire de la transaction a verifier.
                :return: Transaction nettoyee en bytes.
                """

        transaction_temp = dict()
        for key, value in message.items():
            if not key.startswith('_'):
                transaction_temp[key] = value

        # self._logger.debug("Message nettoye: %s" % str(transaction_temp))

        # Premiere passe, converti les dates. Les nombre floats sont incorrects.
        message_json = json.dumps(
            transaction_temp,
            ensure_ascii=False,  # S'assurer de supporter tous le range UTF-8
            cls=DateFormatEncoder
        )

        # HACK - Fix pour le decodage des float qui ne doivent pas finir par .0 (e.g. 100.0 doit etre 100)
        message_json = json.loads(message_json, parse_float=UtilCertificats._parse_float)
        message_json = json.dumps(
            message_json,
            ensure_ascii=False,  # S'assurer de supporter tous le range UTF-8
            sort_keys=True,
            separators=(',', ':')
        )

        message_bytes = bytes(message_json, 'utf-8')

        return message_bytes

    @staticmethod
    def _parse_float(f: str):
        """
        Permet de transformer les nombre floats qui finissent par .0 en entier. Requis pour interoperabilite avec
        la verification (hachage, signature) en JavaScript qui fait cette conversion implicitement.
        :param f:
        :return:
        """
        val_float = float(f)
        val_int = int(val_float)
        if val_int == val_float:
            return val_int
        return val_float

    def _charger_certificat(self):
        try:
            cle = self._contexte.configuration.cle
            self._certificat = cle.cert
            self._chaine = cle.chaine
        except:
            certfile_path = self.configuration.pki_certfile
            self._certificat = self._charger_pem(certfile_path)

    def _charger_pem(self, certfile_path):
        with open(certfile_path, "rb") as certfile:
            pem_bytes = certfile.read()
            pem_str = pem_bytes.decode('utf-8')
            self._chaine = self.__get_chaine_certificats(pem_str)
            certificat = x509.load_pem_x509_certificate(
                pem_bytes,
                backend=default_backend()
            )

        return certificat

    def _charger_cle_privee(self):
        try:
            cle = self._contexte.configuration.cle
            key_bytes = cle.private_key_bytes
        except:
            keyfile_path = self.configuration.pki_keyfile
            with open(keyfile_path, "rb") as keyfile:
                key_bytes = keyfile.read()

        cle = serialization.load_pem_private_key(
            key_bytes,
            password=None,
            backend=default_backend()
        )
        self._cle = cle

    def hacher_contenu(self, dict_message, hachage='sha2-512'):
        """
        Produit un hash SHA-2 256bits du contenu d'un message. Exclue l'en-tete et les elements commencant par _.
        :param dict_message:
        :return:
        """
        # dict_message_effectif = dict_message.copy()
        # del dict_message_effectif['en-tete']  # Retirer l'en-tete, on ne fait que hacher le contenu du dict
        dict_message_effectif = dict()
        for key, value in dict_message.items():
            if not key.startswith('_') and key != Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE:
                dict_message_effectif[key] = value

        message_bytes = self.preparer_transaction_bytes(dict_message_effectif)

        # if hachage is None:
        #     hachage = self._contenu_hash_function()
        #
        # digest = hashes.Hash(hachage, backend=default_backend())
        # digest.update(message_bytes)
        # resultat_digest = digest.finalize()
        # digest_base64 = hachage.name + '_b64:' + str(base64.b64encode(resultat_digest), 'utf-8')
        # self._logger.debug("Resultat hash contenu: %s" % digest_base64)
        #
        # return digest_base64

        hacher(message_bytes, hashing_code=hachage)

    def hacher_bytes(self, enveloppe_bytes: bytes, hachage='sha2-512', encoding='base58btc'):
        """
        Produit un hash SHA-2 256bits du contenu d'un message. Exclue l'en-tete et les elements commencant par _.
        :param enveloppe_bytes:
        :param hachage:
        :param encoding:
        :return:
        """
        # if hachage is None:
        #     hachage = self._contenu_hash_function()
        # digest = hashes.Hash(hachage, backend=default_backend())
        # digest.update(enveloppe_bytes)
        # resultat_digest = digest.finalize()
        # digest_base64 = hachage.name + '_b64:' + str(base64.b64encode(resultat_digest), 'utf-8')
        # self._logger.debug("Resultat hash contenu: %s" % digest_base64)
        #
        # return digest_base64
        hacher(enveloppe_bytes, hashing_code=hachage, encoding=encoding)

    def chiffrage_asymmetrique(self, cle_secrete):
        public_key = self.certificat.public_key()
        cle_secrete_backup = public_key.encrypt(
            cle_secrete,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        fingerprint = self._enveloppe.fingerprint
        return cle_secrete_backup, fingerprint

    def dechiffrage_asymmetrique(self, contenu: Union[bytes, str]) -> bytes:
        """
        Utilise la cle privee en memoire pour dechiffrer le contenu.
        :param contenu:
        :return:
        """
        if isinstance(contenu, str):
            contenu = contenu.encode('utf-8')

        contenu_bytes = multibase.decode(contenu)

        contenu_dechiffre = self._cle.decrypt(
            contenu_bytes,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return contenu_dechiffre

    def emettre_certificat(self, chaine_pem: list, correlation_csr: str = None):
        """
        Emet un certificat avec sa chaine comme evenement a etre capture par les modules interesses.
        :param chaine_pem:
        :param correlation_csr:
        :return:
        """
        enveloppe = EnveloppeCertificat(certificat_pem=chaine_pem[0])
        fingerprint = enveloppe.fingerprint

        message = {
            ConstantesSecurityPki.LIBELLE_FINGERPRINT: fingerprint,
            ConstantesSecurityPki.LIBELLE_CHAINE_PEM: chaine_pem,
        }
        if correlation_csr is not None:
            message[ConstantesSecurityPki.LIBELLE_CORRELATION_CSR] = correlation_csr

        # Emet le certificat sur l'exchange par defaut
        routing = Constantes.ConstantesPki.EVENEMENT_CERTIFICAT_EMIS
        self._contexte.generateur_transactions.emettre_message(message, routing)

        return message

    def valider_x509_enveloppe(self, enveloppe: EnveloppeCertificat,
                               date_reference: datetime.datetime = None):
        """
        Valide une enveloppe
        :param enveloppe:
        :param date_reference:
        :return: Resultat de validation (toujours valide)
        :raises certvalidator.errors.PathBuildingError: Si le path est invalide
        """
        cert_pem = enveloppe.certificat_pem.encode('utf-8')
        inter_list = list()

        # self._logger.debug("CERT PEM :\n%s" % enveloppe.certificat_pem)
        for pem in enveloppe.reste_chaine_pem:
            # self._logger.debug("Chaine PEM :\n%s" % pem.strip())
            inter_list.append(pem.strip().encode('utf-8'))

        if date_reference is not None:
            # batir un contexte avec la date
            validation_context = ValidationContext(moment=date_reference, trust_roots=[self.__cert_millegrille])
        else:
            validation_context = self.__validation_context

        # Verifier le certificat - noter qu'une exception est lancee en cas de probleme
        try:
            validator = CertificateValidator(
                cert_pem, intermediate_certs=inter_list, validation_context=validation_context)
            resultat = validator.validate_usage({'digital_signature'})
            enveloppe.set_est_verifie(True)
            return resultat
        except PathValidationError as pve:
            msg = pve.args[0]
            if 'expired' in msg:
                self._logger.info("Un des certificats est expire, verifier en fonction de la date de reference")
                # Le certificat est expire, on fait la validation pour la fin de la periode de validite
                date_reference = enveloppe.not_valid_after

                validation_context = ValidationContext(moment=date_reference, trust_roots=[self.__cert_millegrille])
                validator = CertificateValidator(
                    cert_pem, intermediate_certs=inter_list, validation_context=validation_context)
                try:
                    resultat = validator.validate_usage({'digital_signature'})
                    enveloppe.set_est_verifie(True)
                    raise CertificatExpire()  # La chaine est valide pour une date anterieure
                except PathValidationError as pve:
                    if self._logger.isEnabledFor(logging.DEBUG):
                        self._logger.exception("Erreur validation path certificat")
                    else:
                        self._logger.info("Erreur validation path certificat : %s", str(pve))
            else:
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.exception("Erreur validation path certificat")
                else:
                    self._logger.info("Erreur validation path certificat : %s", str(pve))
                raise pve

        except PathBuildingError as pbe:
            # Verifier si on a une millegrille tierce
            dernier_cert_pem = inter_list[-1]
            dernier_cert = EnveloppeCertificat(certificat_pem=dernier_cert_pem)
            if dernier_cert.is_rootCA:
                idmg = dernier_cert.idmg
                # Verifier si le idmg est dans la liste des idmg autorises
                autorisation = self.__autorisations_idmg.get(idmg)
                if autorisation is None:
                    # Pas autorise, lancer l'exception
                    raise pbe
                elif autorisation.get('domaines_permis'):
                    # Valider la chaine en fonction de la racine fournie
                    if date_reference is not None:
                        # batir un contexte avec la date
                        validation_context = ValidationContext(moment=date_reference,
                                                               trust_roots=[self.__cert_millegrille, dernier_cert_pem])
                    else:
                        validation_context = ValidationContext(trust_roots=[self.__cert_millegrille, dernier_cert_pem])

                    validator = CertificateValidator(
                        cert_pem, intermediate_certs=inter_list, validation_context=validation_context)

                    validator.validate_usage({'digital_signature'})

                    # Valide, on lance une exception pour indiquer la condition de validite (business rule)
                    raise AutorisationConditionnelleDomaine(autorisation['domaines_permis'], idmg, enveloppe)

    @property
    def certificat(self) -> x509.Certificate:
        return self._certificat

    @property
    def chaine_certs(self) -> list:
        return self._chaine

    def __get_chaine_certificats(self, pem_str: str) -> list:
        chaine_certs = [c + UtilCertificats.END_CERTIFICATE for c in pem_str.split(UtilCertificats.END_CERTIFICATE)]
        return chaine_certs[0:-1]

    def split_chaine_certificats(self, pem_str: str):
        return self.__get_chaine_certificats(pem_str)

    @property
    def enveloppe_certificat_courant(self) -> EnveloppeCertificat:
        return self._enveloppe

    def get_enveloppe_millegrille(self) -> EnveloppeCertificat:
        if self._chaine is not None:
            pem_millegrille = self._chaine[-1]
            return EnveloppeCertificat(certificat_pem=pem_millegrille)

    @property
    def configuration(self):
        return self._contexte.configuration

    @property
    def contexte(self):
        return self._contexte


class SignateurTransaction(UtilCertificats):
    """ Signe une transaction avec le certificat du noeud. """

    def __init__(self, contexte):
        super().__init__(contexte)
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

        # Ajouter information du certification dans l'en_tete
        fingerprint_cert = self._enveloppe.fingerprint
        # self._logger.debug("Fingerprint: %s" % fingerprint_cert)
        en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT] = fingerprint_cert

        signature = self._produire_signature(dict_message_effectif)
        dict_message_effectif[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE] = signature

        return dict_message_effectif

    def _produire_signature(self, dict_message):
        message_bytes = self.preparer_transaction_bytes(dict_message)
        self._logger.debug("Message en format json: %s" % message_bytes)

        # Hacher le message avec BLAKE2b pour supporter message de grande taille avec Ed25519
        hash = hashes.Hash(hashes.BLAKE2b(64))
        hash.update(message_bytes)
        hash_value = hash.finalize()

        signature = self._cle.sign(
            hash_value,
            # asymmetric.padding.PSS(
            #     mgf=asymmetric.padding.MGF1(self._sign_hash_function()),
            #     # salt_length=asymmetric.padding.PSS.MAX_LENGTH
            #     salt_length=64   # Maximum supporte sur iPhone
            # ),
            # self._sign_hash_function()
        )
        # signature_texte_utf8 = str(base64.b64encode(signature), 'utf-8')

        VERSION_SIGNATURE = 2
        signature = bytes([VERSION_SIGNATURE]) + signature

        signature_encodee = multibase.encode('base64', signature).decode('utf-8')
        self._logger.debug("Signature: %s" % signature_encodee)

        return signature_encodee

    def emettre_certificat(self, chaine_pem: list = None, correlation_csr: str = None):
        """
        Emet la chaine de certificat
        :param chaine_pem: Si None, emet le certificat du signateur
        :param correlation_csr:
        :return:
        """
        if chaine_pem is None:
            # Charger la chaine de certificat de signature
            chaine_pem = self.chaine_certs

        super().emettre_certificat(chaine_pem, correlation_csr)


class GestionnaireEvenementsCertificat(UtilCertificats, BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte=contexte)
        self.__channel = None
        self.__queue_reponse = None
        self.__routing_cert = None
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initialiser(self):
        self.__logger.debug("Initialisation GestionnaireEvenementsCertificat")
        super().initialiser()

        if self.contexte.message_dao is not None:
            self.contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel
        self.__channel.queue_declare(queue='', exclusive=True, callback=self.register_mq_handler)

    def register_mq_handler(self, queue):
        nom_queue = queue.method.queue
        self.__queue_reponse = nom_queue

        self.__logger.debug("Transmission certificat PKI a l'initialisation")
        signateur_transactions = self.contexte.signateur_transactions
        signateur_transactions.emettre_certificat()

        enveloppe = signateur_transactions.enveloppe_certificat_courant
        fingerprint = enveloppe.fingerprint
        routing_key = '%s.%s' % (ConstantesSecurityPki.EVENEMENT_REQUETE, fingerprint)

        exchange_defaut = self.configuration.exchange_defaut
        self.__channel.queue_bind(queue=nom_queue, exchange=exchange_defaut, routing_key=routing_key, callback=None)
        self.__channel.basic_consume(nom_queue, self.callbackAvecAck, auto_ack=True)
        self.__routing_cert = routing_key

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def traiter_message(self, ch, method, properties, body):
        # Implementer la lecture de messages, specialement pour transmettre un certificat manquant
        routing_key = method.routing_key
        if routing_key == self.__routing_cert:
            # Transmettre notre certificat
            self.contexte.signateur_transactions.emettre_certificat()
        else:
            raise Exception("Routing non gere: %s" % routing_key)

    @property
    def _message_dao(self):
        return self.contexte.message_dao


class GenerateurEd25519:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def generer_keypair(self):
        self.__logger.debug("Generer keypair")
        keypair = asymmetric.ed25519.Ed25519PrivateKey.generate()
        return keypair

    def generer_private_openssh(self) -> bytes:
        keypair = self.generer_keypair()
        private_bytes = keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )

        # public_key = keypair.public_key()
        # public_bytes = public_key.public_bytes(
        #     encoding=serialization.Encoding.OpenSSH,
        #     format=serialization.PublicFormat.OpenSSH
        # )
        # logger.debug("Public Key\n%s mathieu@serveur1" % public_bytes.decode('utf-8'))

        return private_bytes


class GenerateurRsa:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def generer_keypair(self):
        self.__logger.debug("Generer keypair")
        keypair = asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        return keypair

    def generer_private_openssh(self) -> bytes:
        keypair = self.generer_keypair()
        private_bytes = keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_bytes


class GenerateurEd25519:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def generer_keypair(self):
        self.__logger.debug("Generer keypair")
        keypair = Ed25519PrivateKey.generate()

        return keypair

    def generer_private_openssh(self) -> bytes:
        keypair = self.generer_keypair()
        private_bytes = keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_bytes


class CertificatInvalide(Exception):
    def __init__(self, message, errors=None, key_subject_identifier=None):
        super().__init__(message, errors)
        self.errors = errors
        self.__key_subject_identifier = key_subject_identifier

    @property
    def key_subject_identifier(self):
        return self.__key_subject_identifier


class HachageInvalide(Exception):
    def __init__(self, message, errors=None):
        super().__init__(message, errors)
        self.errors = errors


class AutorisationConditionnelleDomaine(Exception):
    """
    Lancee pour indiquer que le certificat/chaine recu sont invalides pour la MilleGrille
    locale (root) mais globalement valide pour les domaines dans la liste.
    """

    def __init__(self, domaines, idmg, enveloppe: EnveloppeCertificat):
        super().__init__('AutorisationConditionnelleDomaine: %s' % str(domaines))
        self.domaines = domaines
        self.idmg = idmg
        self.enveloppe = enveloppe


class CertificatExpire(Exception):
    pass

# Module pour la securite avec certificats (PKI)
import logging
import json
import re
import base64
import binascii
import os
import datetime
import pytz

from typing import Optional
from cryptography.hazmat.primitives import serialization, asymmetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesSecurityPki
from millegrilles.dao.MessageDAO import BaseCallback, CertificatInconnu
from millegrilles.util.JSONMessageEncoders import DateFormatEncoder
from millegrilles.util.IdmgUtil import IdmgUtil
from millegrilles.config.Autorisations import autorisations_idmg


class EnveloppeCertificat:
    """ Encapsule un certificat. """

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

    @staticmethod
    def calculer_fingerprint(certificat):
        return certificat.fingerprint(hashes.SHA1())

    @staticmethod
    def calculer_fingerprint_sha256(certificat):
        return certificat.fingerprint(hashes.SHA256())

    @staticmethod
    def calculer_fingerprint_ascii(certificat):
        return str(binascii.hexlify(EnveloppeCertificat.calculer_fingerprint(certificat)), 'utf-8')

    @staticmethod
    def calculer_fingerprint_b64(certificat):
        return str(base64.b64encode(EnveloppeCertificat.calculer_fingerprint(certificat)), 'utf-8')

    def __split_chaine_certificats(self, pem_str: str):
        chaine_certs = [c + UtilCertificats.END_CERTIFICATE for c in pem_str.split(UtilCertificats.END_CERTIFICATE)]
        return chaine_certs[0:-1]

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def fingerprint_ascii(self):
        return str(binascii.hexlify(self._fingerprint), 'utf-8')

    @property
    def fingerprint_b64(self):
        return str(base64.b64encode(self.fingerprint), 'utf-8')

    @property
    def fingerprint_sha256_b64(self):
        return str(base64.b64encode(EnveloppeCertificat.calculer_fingerprint_sha256(self._certificat)), 'utf-8')

    @property
    def fingerprint_base58(self):
        """
        Retourne le idmg
        """
        return self.idmg

    @property
    def idmg(self) -> str:
        """
        Retourne le idmg du certificat.
        Calcule avec SHA-512/224 retourne en base58
        """
        util = IdmgUtil()
        idmg = util.encoder_idmg_cert(self._certificat)
        return idmg

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
    def not_valid_before(self):
        return self._certificat.not_valid_before

    @property
    def not_valid_after(self):
        return self._certificat.not_valid_after

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
        return (now > self.certificat.not_valid_before) and (now < self.certificat.not_valid_after)

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


class UtilCertificats:

    END_CERTIFICATE = '-----END CERTIFICATE-----'

    def __init__(self, contexte):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._contexte = contexte
        self._sign_hash_function = hashes.SHA512
        self._contenu_hash_function = hashes.SHA256

        self._certificat: Optional[str] = None
        self._cle = None
        self._enveloppe: Optional[EnveloppeCertificat] = None
        self._chaine: Optional[list] = None

        self.__validation_context: Optional[ValidationContext] = None
        self.__cert_millegrille: Optional[bytes] = None
        self.__autorisations_idmg = autorisations_idmg()  # Autorisations pour idmg tierces

    def initialiser(self):
        # Charger le contexte de validation
        with open(self._contexte.configuration.mq_cafile, 'rb') as fichier:
            self.__cert_millegrille = fichier.read()
        self.__validation_context = ValidationContext(trust_roots=[self.__cert_millegrille])

        self._charger_cle_privee()
        self._charger_certificat()

        self._enveloppe = EnveloppeCertificat(certificat_pem='\n'.join(self._chaine))

        # Verifier que le certificat peut bien etre utilise pour signer des transactions
        # Valide aussi la chaine et les dates d'expiration
        self.valider_x509_enveloppe(self._enveloppe)

    def preparer_transaction_bytes(self, transaction_dict):
        """
        Prepare une transaction (dictionnaire) pour la signature ou la verification. Retourne des bytes.

        :param transaction_dict: Dictionnaire de la transaction a verifier.
        :return: Transaction nettoyee en bytes.
        """

        transaction_temp = dict()
        for key, value in transaction_dict.items():
            if not key.startswith('_'):
                transaction_temp[key] = value

        # self._logger.debug("Message nettoye: %s" % str(transaction_temp))

        # Premiere passe, converti les dates. Les nombre floats sont incorrects.
        message_json = json.dumps(
            transaction_temp,
            ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
            cls=DateFormatEncoder
        )

        # HACK - Fix pour le decodage des float qui ne doivent pas finir par .0 (e.g. 100.0 doit etre 100)
        message_json = json.loads(message_json, parse_float=self._parse_float)
        message_json = json.dumps(
            message_json,
            ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
            sort_keys=True,
            separators=(',', ':')
        )

        message_bytes = bytes(message_json, 'utf-8')

        return message_bytes

    def _parse_float(self, f: str):
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
        keyfile_path = self.configuration.pki_keyfile
        with open(keyfile_path, "rb") as keyfile:
            cle = serialization.load_pem_private_key(
                keyfile.read(),
                password=None,
                backend=default_backend()
            )
            self._cle = cle

    def hacher_contenu(self, dict_message, hachage=None):
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

        if hachage is None:
            hachage = self._contenu_hash_function()

        digest = hashes.Hash(hachage, backend=default_backend())
        digest.update(message_bytes)
        resultat_digest = digest.finalize()
        digest_base64 = hachage.name + '_b64:' + str(base64.b64encode(resultat_digest), 'utf-8')
        self._logger.debug("Resultat hash contenu: %s" % digest_base64)

        return digest_base64

    def hacher_bytes(self, enveloppe_bytes: bytes, hachage=None):
        """
        Produit un hash SHA-2 256bits du contenu d'un message. Exclue l'en-tete et les elements commencant par _.
        :param dict_message:
        :return:
        """
        if hachage is None:
            hachage = self._contenu_hash_function()

        digest = hashes.Hash(hachage, backend=default_backend())
        digest.update(enveloppe_bytes)
        resultat_digest = digest.finalize()
        digest_base64 = hachage.name + '_b64:' + str(base64.b64encode(resultat_digest), 'utf-8')
        self._logger.debug("Resultat hash contenu: %s" % digest_base64)

        return digest_base64

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
        fingerprint = self._enveloppe.fingerprint_ascii
        return cle_secrete_backup, fingerprint

    def dechiffrage_asymmetrique(self, contenu) -> bytes:
        """
        Utilise la cle privee en memoire pour dechiffrer le contenu.
        :param contenu:
        :return:
        """
        contenu_bytes = base64.b64decode(contenu)

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
        fingerprint = enveloppe.fingerprint_ascii
        fingerprint_sha256_b64 = enveloppe.fingerprint_sha256_b64

        message = {
            ConstantesSecurityPki.LIBELLE_FINGERPRINT: fingerprint,
            ConstantesSecurityPki.LIBELLE_FINGERPRINT_SHA256_B64: fingerprint_sha256_b64,
            ConstantesSecurityPki.LIBELLE_CHAINE_PEM: chaine_pem,
        }
        if correlation_csr is not None:
            message[ConstantesSecurityPki.LIBELLE_CORRELATION_CSR] = correlation_csr

        # Emet le certificat sur l'exchange par defaut
        routing = Constantes.ConstantesPki.EVENEMENT_CERTIFICAT_EMIS
        self._contexte.generateur_transactions.emettre_message(message, routing)

    def valider_x509_enveloppe(self, enveloppe: EnveloppeCertificat,
                               date_reference: datetime.datetime = None,
                               ignorer_date=False):
        """
        Valide une enveloppe
        :param enveloppe:
        :param date_reference:
        :param ignorer_date: Charger le certificat en utilisation date courante ou fin de periode de validite
        :return: Resultat de validation (toujours valide)
        :raises certvalidator.errors.PathBuildingError: Si le path est invalide
        """
        cert_pem = enveloppe.certificat_pem.encode('utf-8')
        inter_list = list()

        # self._logger.debug("CERT PEM :\n%s" % enveloppe.certificat_pem)
        for pem in enveloppe.reste_chaine_pem:
            # self._logger.debug("Chaine PEM :\n%s" % pem.strip())
            inter_list.append(pem.strip().encode('utf-8'))

        if date_reference is not None or ignorer_date:
            if ignorer_date:
                # Le certificat est expire, on fait la validation pour la fin de la periode de validite
                date_reference = pytz.UTC.localize(enveloppe.not_valid_after)

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
        except PathValidationError as pve:
            msg = pve.args[0]
            if 'expired' in msg:
                self._logger.info("Un des certificats est expire, verifier en fonction de la date de reference")

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
                    if date_reference is not None or ignorer_date:
                        if ignorer_date:
                            # Le certificat est expire, on fait la validation pour la fin de la periode de validite
                            date_reference = pytz.UTC.localize(enveloppe.not_valid_after)

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

        return resultat

    @property
    def certificat(self):
        return self._certificat

    @property
    def chaine_certs(self):
        return self._chaine

    def __get_chaine_certificats(self, pem_str: str):
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

        return None

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
        fingerprint_cert = self._enveloppe.fingerprint_sha256_b64
        # self._logger.debug("Fingerprint: %s" % fingerprint_cert)
        en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT] = 'sha256_b64:' + fingerprint_cert

        signature = self._produire_signature(dict_message_effectif)
        dict_message_effectif[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE] = signature

        return dict_message_effectif

    def contresigner(self, message: dict, idmg: str):
        """
        Ajoute une signature au message sans modifier l'entete. Utilise pour re-signer un message avec un
        certificat de MilleGrilles tierce
        :param message:
        :return:
        """
        contresignatures = message.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_CONTRESIGNATURES)
        if contresignatures is None:
            contresignatures = dict()
            message[Constantes.TRANSACTION_MESSAGE_LIBELLE_CONTRESIGNATURES] = contresignatures

        contresignature = dict()
        contresignatures[idmg] = contresignature

        signature = self._produire_signature(message)
        contresignature[Constantes.TRANSACTION_MESSAGE_LIBELLE_CONTRESIGNATURE] = signature
        contresignature[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT] = \
            self._enveloppe.fingerprint_ascii

    def _produire_signature(self, dict_message):
        message_bytes = self.preparer_transaction_bytes(dict_message)
        self._logger.debug("Message en format json: %s" % message_bytes)

        signature = self._cle.sign(
            message_bytes,
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(self._sign_hash_function()),
                # salt_length=asymmetric.padding.PSS.MAX_LENGTH
                salt_length=64   # Maximum supporte sur iPhone
            ),
            self._sign_hash_function()
        )

        signature_texte_utf8 = str(base64.b64encode(signature), 'utf-8')
        self._logger.debug("Signatures: %s" % signature_texte_utf8)

        return signature_texte_utf8

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


class VerificateurTransaction(UtilCertificats):
    """ Verifie la signature des transactions. """

    def __init__(self, contexte):
        super().__init__(contexte.configuration)
        self._contexte = contexte
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
        elif isinstance(transaction, dict):
            dict_message = transaction.copy()
        else:
            raise TypeError("La transaction doit etre en format str ou dict")

        hachage = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE]
        if hachage is None:
            raise ValueError("Le %s n'existe pas sur la transaction" % Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE)

        signature = dict_message['_signature']

        if signature is None:
            raise ValueError("La _signature n'existe pas sur la transaction")

        # Verifier le hachage du contenu
        hachage_contenu_courant = self.hacher_contenu(dict_message)
        if hachage != hachage_contenu_courant:
            raise HachageInvalide("Le hachage %s ne correspond pas au contenu recu %s" % (
                hachage, hachage_contenu_courant
            ))
        self._logger.debug("Hachage de la transaction est OK: %s" % hachage_contenu_courant)

        regex_ignorer = re.compile('^_.+')
        keys = list()
        keys.extend(dict_message.keys())
        for cle in keys:
            m = regex_ignorer.match(cle)
            if m:
                del dict_message[cle]
                self._logger.debug("Enlever cle: %s" % cle)

        # Verifier que le cert CA du message == IDMG du message. Charge le CA racine et intermediaires connus de
        # la MilleGrille tierce dans un fichier (idmg.racine.pem et idmg.untrusted.cert.pem) au besoin.
        # Retourne le idmg de la MilleGrille concernee.
        exception_si_valide = None  # Exception a lancer si la signature est valide mais que le certificat est conditionnellement valide
        try:
            enveloppe_certificat = self._identifier_certificat(dict_message)
        except CertificatInconnu as ci:
            # Le certificat est inconnu. Verifier si le message contient une fiche (privee ou publique)
            # ou des certificats inline
            certificats_inline = transaction.get('_certificats') or transaction.get('_certificat')
            if certificats_inline:
                # Charger les nouveaux certificats associes au message
                # for cert in certificats_inline:
                #     # Emettre le certificat sur MQ
                #     enveloppe_temp = EnveloppeCertificat(certificat_pem=cert)
                #     # self.contexte.generateur_transactions.emettre_certificat(cert, enveloppe_temp.fingerprint_ascii)
                #     # self.emettre_certificat(certificats_inline)
                try:
                    epoch_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
                    date_reference = datetime.datetime.fromtimestamp(epoch_transaction, tz=pytz.UTC)
                except KeyError:
                    date_reference = datetime.datetime.now(tz=pytz.UTC)

                enveloppe_temp = EnveloppeCertificat(certificat_pem='\n'.join(certificats_inline))

                # Tenter de valider le certificat immediatement, peut echouer si la chaine n'a pas ete traitee
                try:
                    enveloppe_certificat = self._contexte.verificateur_certificats.charger_certificat(
                        enveloppe=enveloppe_temp, date_reference=date_reference)
                    self._contexte.verificateur_certificats.emettre_certificat(certificats_inline)
                except AutorisationConditionnelleDomaine as acd:
                    self._contexte.verificateur_certificats.emettre_certificat(certificats_inline)
                    raise acd

            else:
                # Verifier cas speciaux
                enveloppe_certificat = None
                entete = dict_message.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE)
                if entete is not None:
                    domaine_action = entete.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE)
                    if domaine_action == Constantes.ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT:

                        # C'est une transaction de certificats, on fait juste charger le contenu directement
                        pems = [dict_message[ConstantesSecurityPki.LIBELLE_CERTIFICATS_PEM][fp]
                                for fp in dict_message[ConstantesSecurityPki.LIBELLE_CHAINE]]

                        enveloppe_certificat = EnveloppeCertificat(certificat_pem='\n'.join(pems))

                # fiche = dict_message.get('fiche_privee')
                # certs_signataires = dict_message.get('certificat_fullchain_signataire')
                # if fiche is not None:
                #     self._logger.info("Message avec une fichier privee, on charge les certificats")
                #     self._charger_fiche(fiche, certs_signataires)
                #     enveloppe_certificat = self._identifier_certificat(dict_message)
                # else:
                if enveloppe_certificat is None:
                    self._logger.info("Certificat inconnu, requete MQ pour trouver %s" % ci.fingerprint)
                    # routing = ConstantesSecurityPki.EVENEMENT_REQUETE + '.' + ci.fingerprint
                    # Utiliser emettre commande pour eviter d'ajouter un prefixe au routage
                    self.contexte.message_dao.transmettre_demande_certificat(ci.fingerprint)
                    raise ci  # On re-souleve l'erreur

        except AutorisationConditionnelleDomaine as acd:
            # Le certificat est valide, mais seulement pour certains domaines
            # On verifie la signature de la transation. Si elle est valide, on relance l'exception
            # Sinon on laise l'erreur de signature etre lancee
            exception_si_valide = acd
            enveloppe_certificat = acd.enveloppe

        self._logger.debug(
            "Certificat utilise pour verification signature message: %s" % enveloppe_certificat.fingerprint_sha256_b64)

        self._verifier_signature(dict_message, signature, enveloppe=enveloppe_certificat)

        if exception_si_valide is not None:
            # On a une exception qui doit etre lancee uniquement quand la signature est valide
            raise exception_si_valide

        return enveloppe_certificat

    def _verifier_signature(self, dict_message, signature, enveloppe=None):
        """
        Verifie la signature du message avec le certificat.

        :param dict_message:
        :param signature:
        :param enveloppe: Optionnel. Certificat a utiliser pour la verification de signature
        :raises InvalidSignature: Lorsque la signature est invalide
        :return:
        """
        if enveloppe is not None:
            certificat = enveloppe.certificat
            self._logger.debug("Verifier signature, Certificat: %s" % enveloppe.fingerprint_ascii)
        else:
            certificat = self.certificat

        signature_bytes = base64.b64decode(signature)
        # message_json = json.dumps(dict_message, sort_keys=True, separators=(',', ':'))
        # message_bytes = bytes(message_json, 'utf-8')
        message_bytes = self.preparer_transaction_bytes(dict_message)
        # self._logger.debug("Verifier signature, Message: %s" % str(dict_message))

        cle_publique = certificat.public_key()
        cle_publique.verify(
            signature_bytes,
            message_bytes,
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(self._sign_hash_function()),
                salt_length=64  # max supporte sur iPhone asymmetric.padding.PSS.MAX_LENGTH
            ),
            self._sign_hash_function()
        )
        self._logger.debug("Signature OK")

    def _identifier_certificat(self, dict_message):
        """
        Identifie le certificat, tente de le charger au besoin.

        :param dict_message:
        :return:
        """

        fingerprint = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT]
        self._logger.debug("Identifier certificat transaction, fingerprint %s" % fingerprint)
        verificateur_certificats = self._contexte.verificateur_certificats

        try:
            epoch_transaction = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
            date_reference = datetime.datetime.fromtimestamp(epoch_transaction, tz=pytz.UTC)
        except KeyError:
            date_reference = datetime.datetime.now(tz=pytz.UTC)

        enveloppe_certificat = verificateur_certificats.charger_certificat(fingerprint=fingerprint, date_reference=date_reference)

        return enveloppe_certificat

    def _charger_fiche(self, fiche, certs_signataires: list = None):
        """
        Charge et emet les certificats valides d'une fiche de MilleGrille
        """
        verificateur_certificats = self._contexte.verificateur_certificats
        enveloppes_certificats = verificateur_certificats.charger_fiche(fiche, certs_signataires)

        # Les certificats de la fiche ont ete charges et sont valides. On les emet sur le reseau.
        for cert in enveloppes_certificats:
            self.contexte.generateur_transactions.emettre_certificat(cert.certificat_pem, cert.fingerprint_ascii)

        return enveloppes_certificats


class VerificateurCertificats(UtilCertificats):
    """
    Verifie les certificats en utilisant les certificats CA et openssl.

    Charge les certificats en utilisant le fingerprint (inclu dans les transactions). Si un certificat n'est pas
    connu, le verificateur va tenter de le trouver dans MongoDB. Si le certificat n'existe pas dans Mongo,
    une erreur est lancee via RabbitMQ pour tenter de trouver le certificat via un des noeuds.
    """

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._cache_certificats_fingerprint = dict()

    def charger_certificat(self, fichier=None, fingerprint: str = None, enveloppe: EnveloppeCertificat = None,
                           date_reference: datetime.datetime = None):
        # Tenter de charger a partir d'une copie locale
        if fingerprint is not None:
            # Split fingerprint au besoin
            fingerprint = fingerprint.split(':')[-1]

            # Verifier si le certificat est deja charge
            enveloppe = self._cache_certificats_fingerprint.get(fingerprint)

            if enveloppe is None:
                collection = self._contexte.document_dao.get_collection(ConstantesSecurityPki.COLLECTION_NOM)
                document_cert = collection.find_one({ConstantesSecurityPki.LIBELLE_FINGERPRINT_SHA256_B64: fingerprint})
                if document_cert is not None:
                    pems = [document_cert[ConstantesSecurityPki.LIBELLE_CERTIFICATS_PEM][fp] for fp in document_cert[ConstantesSecurityPki.LIBELLE_CHAINE]]
                    enveloppe = EnveloppeCertificat(certificat_pem='\n'.join(pems))

        elif fichier is not None and os.path.isfile(fichier):
            with open(fichier, 'r') as fichier:
                certificat = fichier.read()
            # certificat = self._charger_pem(fichier)

            if certificat is not None:
                enveloppe = EnveloppeCertificat(certificat_pem=certificat)

        # Conserver l'enveloppe dans le cache
        if enveloppe is not None:

            if not enveloppe.est_verifie:
                self.valider_x509_enveloppe(enveloppe, date_reference=date_reference)
                self._cache_certificats_fingerprint[enveloppe.fingerprint_sha256_b64] = enveloppe

        else:
            raise CertificatInconnu("Certificat ne peut pas etre charge", fingerprint=fingerprint)

        return enveloppe

    def aligner_chaine_cas(self, enveloppe: EnveloppeCertificat):
        liste_enveloppes_cas = [enveloppe]
        for cert_pem in enveloppe.reste_chaine_pem:
            liste_enveloppes_cas.append(EnveloppeCertificat(certificat_pem=cert_pem))
        return liste_enveloppes_cas


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
        fingerprint = enveloppe.fingerprint_sha256_b64
        routing_key = '%s.%s' % (ConstantesSecurityPki.EVENEMENT_REQUETE, fingerprint)

        exchange_defaut = self.configuration.exchange_defaut
        self.__channel.queue_bind(queue=nom_queue, exchange=exchange_defaut, routing_key=routing_key, callback=None)
        self.__channel.basic_consume(self.callbackAvecAck, queue=nom_queue, no_ack=False)
        self.__routing_cert = routing_key

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    # def transmettre_certificat(self):
    #     enveloppe = self.enveloppe_certificat_courant
    #
    #     message_evenement = ConstantesSecurityPki.DOCUMENT_EVENEMENT_CERTIFICAT.copy()
    #     message_evenement[ConstantesSecurityPki.LIBELLE_FINGERPRINT] = enveloppe.fingerprint_ascii
    #     message_evenement[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM] = str(
    #         enveloppe.certificat.public_bytes(serialization.Encoding.PEM), 'utf-8'
    #     )
    #
    #     routing = Constantes.ConstantesPki.EVENEMENT_CERTIFICAT_EMIS
    #     self.contexte.signateur_transactions.emettre_certificat()
    #         message_dao.transmettre_message(
    #         message_evenement, routing, channel=self.__channel, exchange='broadcast'
    #     )
    #
    #     return enveloppe

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

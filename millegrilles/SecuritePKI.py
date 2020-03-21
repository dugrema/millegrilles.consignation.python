# Module pour la securite avec certificats (PKI)
import logging
import json
import re
import base64
import binascii
import os
import datetime
import subprocess
import tempfile
import secrets
import base58
import shutil
import math

from cryptography.hazmat.primitives import serialization, asymmetric, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.name import NameOID

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesSecurityPki
from millegrilles.dao.MessageDAO import BaseCallback, CertificatInconnu, JSONHelper
from millegrilles.util.JSONMessageEncoders import DateFormatEncoder


class EnveloppeCertificat:
    """ Encapsule un certificat. """

    def __init__(self, certificat=None, certificat_pem=None, fingerprint=None):
        """
        :param fingerprint: Fingerprint en binascii (lowercase, pas de :) du certificat
        """

        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._est_verifie = False  # Flag qui est change une fois la chaine verifiee

        if certificat_pem is not None:
            if isinstance(certificat_pem, str):
                certificat_pem = bytes(certificat_pem, 'utf-8')
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
    def calculer_fingerprint_ascii(certificat):
        return str(binascii.hexlify(EnveloppeCertificat.calculer_fingerprint(certificat)), 'utf-8')

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def fingerprint_ascii(self):
        return str(binascii.hexlify(self._fingerprint), 'utf-8')

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
        idmg = base58.b58encode(self._certificat.fingerprint(hashes.SHA512_224())).decode('utf-8')
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
        organization = self._certificat.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if len(organization) > 0:
            return organization[0].value
        return None

    @property
    def subject_organizational_unit_name(self):
        org = self._certificat.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if org is not None and len(org) > 0:
            return org[0].value
        return None

    @property
    def subject_common_name(self):
        sujet = self.certificat.subject
        cn = sujet.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
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

    def __init__(self, contexte):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._contexte = contexte
        self._sign_hash_function = hashes.SHA512
        self._contenu_hash_function = hashes.SHA256

        self._certificat = None
        self._cle = None
        self._enveloppe = None

    def initialiser(self):
        self._charger_cle_privee()
        self._charger_certificat()

        # Verifier que le certificat peut bien etre utilise pour signer des transactions
        self._verifier_usage()

        self._enveloppe = EnveloppeCertificat(self.certificat)

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

        self._logger.debug("Message nettoye: %s" % str(transaction_temp))

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

        # print(message_bytes)

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
        certfile_path = self.configuration.mq_certfile
        self._certificat = self._charger_pem(certfile_path)

    def _charger_pem(self, certfile_path):
        with open(certfile_path, "rb") as certfile:
            certificat = x509.load_pem_x509_certificate(
                certfile.read(),
                backend=default_backend()
            )

        return certificat

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

    def hacher_contenu(self, dict_message):
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

        digest = hashes.Hash(self._contenu_hash_function(), backend=default_backend())
        digest.update(message_bytes)
        resultat_digest = digest.finalize()
        digest_base64 = str(base64.b64encode(resultat_digest), 'utf-8')
        self._logger.debug("Resultat hash contenu: %s" % digest_base64)

        return digest_base64

    @property
    def certificat(self):
        return self._certificat

    @property
    def enveloppe_certificat_courant(self) -> EnveloppeCertificat:
        return self._enveloppe

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
        fingerprint_cert = self._enveloppe.fingerprint_ascii
        self._logger.debug("Fingerprint: %s" % fingerprint_cert)
        en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT] = fingerprint_cert

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
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            self._sign_hash_function()
        )

        signature_texte_utf8 = str(base64.b64encode(signature), 'utf-8')
        self._logger.debug("Signatures: %s" % signature_texte_utf8)

        return signature_texte_utf8


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

        self._logger.debug("Message nettoye: %s" % str(dict_message))

        # Verifier que le cert CA du message == IDMG du message. Charge le CA racine et intermediaires connus de
        # la MilleGrille tierce dans un fichier (idmg.racine.pem et idmg.untrusted.cert.pem) au besoin.
        # Retourne le idmg de la MilleGrille concernee.
        try:
            enveloppe_certificat = self._identifier_certificat(dict_message)
        except CertificatInconnu as ci:
            # Le certificat est inconnu. Verifier si le message contient une fiche (privee ou publique)
            fiche = dict_message.get('fiche_privee')
            certs_signataires = dict_message.get('certificat_fullchain_signataire')
            if fiche is not None:
                self._logger.info("Message avec une fichier privee, on charge les certificats")
                self._charger_fiche(fiche, certs_signataires)
                enveloppe_certificat = self._identifier_certificat(dict_message)
            else:
                raise ci  # On re-souleve l'erreur

        self._logger.debug("Certificat utilise pour verification signature message: %s" % enveloppe_certificat.fingerprint_ascii)

        self._verifier_signature(dict_message, signature, enveloppe=enveloppe_certificat)

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
        message_bytes = self.preparer_transaction_bytes(dict_message);
        self._logger.debug("Verifier signature, Message: %s" % str(dict_message))

        cle_publique = certificat.public_key()
        cle_publique.verify(
            signature_bytes,
            message_bytes,
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(self._sign_hash_function()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
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

        fingerprint = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT]
        verificateur_certificats = self._contexte.verificateur_certificats

        enveloppe_certificat = verificateur_certificats.charger_certificat(fingerprint=fingerprint)
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

        self._cache_certificats_ca = dict()
        self._cache_certificats_fingerprint = dict()
        self._liste_CAs_connus = []  # Fingerprint de tous les CAs connus, trusted et untrusted

        self.__workdir = tempfile.mkdtemp(prefix='validation_', dir=self.configuration.pki_workdir)

    def __del__(self):
        self.close()

    def get_par_akid(self, akid):
        return [cert for cert in self._liste_CAs_connus if cert.subject_key_identifier == akid]

    def charger_certificats_CA_millegrille(self, idmg: str):
        """
        Charge le certificat CA d'une MilleGrille tierce s'il est connu avec les certificats intermediaires.
        Aucun effet si le certificat est deja charge.
        """

        file_ca_racine = os.path.join(self.__workdir, idmg + '.racine.cert.pem')
        if not os.path.isfile(file_ca_racine):
            collection = self._contexte.document_dao.get_collection(ConstantesSecurityPki.COLLECTION_NOM)

            filtre = {
                '$or': [
                    {
                        Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesSecurityPki.LIBVAL_CERTIFICAT_RACINE,
                        ConstantesSecurityPki.LIBELLE_IDMG: idmg
                    },
                    {
                        Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesSecurityPki.LIBVAL_CERTIFICAT_MILLEGRILLE,
                        'sujet.commonName': idmg,
                    }
                ]
            }

            certs = collection.find(filtre)

            for cert in certs:
                if cert[Constantes.DOCUMENT_INFODOC_LIBELLE] == ConstantesSecurityPki.LIBVAL_CERTIFICAT_RACINE and \
                        cert[ConstantesSecurityPki.LIBELLE_IDMG] == idmg:
                    # C'est le certificat racine, on re-verifie son fingerprint avant de le sauvegarder sur disque
                    enveloppe_ca = EnveloppeCertificat(certificat_pem=cert[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM])
                    if enveloppe_ca.is_rootCA and enveloppe_ca.idmg == idmg:
                        # Certificat racine est valide
                        self._liste_CAs_connus.append(enveloppe_ca)
                        with open(file_ca_racine, 'w') as fichier:
                            fichier.write(cert[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM])

                        untrusted_cas_filename = os.path.join(self.__workdir, idmg + '.untrusted.cert.pem')
                        with open(untrusted_cas_filename, 'w+'):
                            pass   # Juste touch, initialiser le fichier

                    else:
                        raise CertificatInvalide("Le certificat racine de %s a ete altere (idmg != fingerprint)" % idmg)
                else:
                    # Certificat intermediaire, on l'ajoute au untrusted (pas besoin de verifier ici, c'est untrusted)
                    enveloppe_ca = EnveloppeCertificat(
                        certificat_pem=cert[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM])
                    self._liste_CAs_connus.append(enveloppe_ca)
                    self._ajouter_untrusted_ca(enveloppe_ca)
        else:
            # Certificat racine pour la MilleGrille est deja charge
            pass

    def charger_certificat(self, fichier=None, fingerprint=None, enveloppe=None):
        # Tenter de charger a partir d'une copie locale
        if fingerprint is not None:
            # Verifier si le certificat est deja charge
            enveloppe = self._cache_certificats_fingerprint.get(fingerprint)

            if enveloppe is None:
                collection = self._contexte.document_dao.get_collection(ConstantesSecurityPki.COLLECTION_NOM)
                document_cert = collection.find_one({'fingerprint': fingerprint})
                if document_cert is not None:
                    enveloppe = EnveloppeCertificat(
                        certificat_pem=document_cert[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM]
                    )

        elif fichier is not None and os.path.isfile(fichier):
            certificat = self._charger_pem(fichier)

            if certificat is not None:
                enveloppe = EnveloppeCertificat(certificat)

        # Conserver l'enveloppe dans le cache
        if enveloppe is not None:

            if not enveloppe.est_verifie:

                # S'assurer que le contexte pour cette MilleGrille est charge
                idmg = enveloppe.subject_organization_name
                self.charger_certificats_CA_millegrille(idmg)  # Aucun effet si le cert racine est deja charge

                # Verifier la chaine de ce certificat
                if enveloppe.is_rootCA:
                    self._ajouter_racine(enveloppe)
                else:
                    if enveloppe.is_CA and not enveloppe.is_rootCA:
                        # Ajouter dans le fichier temp des untrusted CAs pour openssl
                        # Note: si le certificat est invalide, c'est possiblement parce que les autorites ne
                        # sont pas chargees en ordre. On le conserve quand meme.
                        if enveloppe.fingerprint_ascii not in self._liste_CAs_connus:
                            self._logger.debug("Conserver cert CA dans untrusted: %s" % enveloppe.fingerprint_ascii)
                            self._ajouter_untrusted_ca(enveloppe)

                        self.verifier_chaine(enveloppe)

                self._cache_certificats_fingerprint[enveloppe.fingerprint_ascii] = enveloppe

        else:
            raise CertificatInconnu("Certificat ne peut pas etre charge", fingerprint=fingerprint)

        return enveloppe

    def aligner_chaine_cas(self, enveloppe: EnveloppeCertificat):
        liste_enveloppes_cas = list()
        depth = 0
        while not enveloppe.is_rootCA and depth < 10:
            autorite = enveloppe.authority_key_identifier
            self._logger.debug("Trouver certificat autorite fingerprint %s" % autorite)
            enveloppes = self._contexte.verificateur_certificats.get_par_akid(autorite)
            if len(enveloppes) > 1:
                raise ValueError("Bug - on ne supporte pas plusieurs cert par AKID - TO DO")
            try:
                enveloppe = enveloppes[0]
            except IndexError:
                # Le certificat n'est pas trouve, tenter de charger la chaine
                enveloppe = self.charger_certificat(enveloppe=enveloppe)
                continue  # Recommencer la verification

            liste_enveloppes_cas.append(enveloppe)
            self._logger.debug("Certificat akid %s trouve, fingerprint %s" % (autorite, enveloppe.fingerprint_ascii))

            depth = depth + 1

        if depth == 10:
            raise ValueError("Limite de profondeur de chain de certificat atteint")

        return liste_enveloppes_cas

    def _ajouter_racine(self, enveloppe: EnveloppeCertificat):

        idmg = enveloppe.idmg

        trusted_ca_filename = os.path.join(self.__workdir, idmg + '.racine.cert.pem')
        try:
            with open(trusted_ca_filename, 'w') as writer:
                writer.write(enveloppe.certificat_pem)

            os.chmod(trusted_ca_filename, 0o444)
        except PermissionError:
            self._logger.info("Tentative de sauvegarder plusieurs fois le cert racine %s" % idmg)

    def _ajouter_untrusted_ca(self, enveloppe: EnveloppeCertificat):

        idmg = enveloppe.subject_organization_name

        untrusted_cas_filename = os.path.join(self.__workdir, idmg + '.untrusted.cert.pem')
        with open(untrusted_cas_filename, 'w+') as untrusted_cas_writer:
            untrusted_cas_writer.write(enveloppe.certificat_pem)

        os.chmod(untrusted_cas_filename, 0o644)

    def verifier_chaine(self, enveloppe: EnveloppeCertificat):
        """
        Utilise les root CA et untrusted CAs pour verifier la chaine du certificat
        :return: True si le certificat est valide selon la chaine de certification, date, etc (openssl).
        """
        idmg = enveloppe.subject_organization_name
        untrusted_cas_filename = os.path.join(self.__workdir, idmg + '.untrusted.cert.pem')
        if idmg == self.configuration.idmg:
            # MilleGrille locale - on utilise le fichier CA pre-configure
            trusted_ca_filename = self.configuration.pki_cafile
        else:
            # MilleGrille distante, on utilise un fichier CA recu
            trusted_ca_filename = os.path.join(self.__workdir, idmg + '.racine.cert.pem')

        nom_fichier_tmp = tempfile.mktemp(suffix='.cert.pem', dir=self.__workdir)
        with open(nom_fichier_tmp, 'w') as output_cert_file :
            output_cert_file.write(enveloppe.certificat_pem)

            # Flush le contenu, mais on garde le write lock sur le fichier pour eviter
            # qu'il soit altere par un autre processus.
            output_cert_file.flush()

            self._logger.debug("Cert Racine: %s, untrusted: %s" % (trusted_ca_filename, untrusted_cas_filename))

            commande_openssl = [
                'openssl', 'verify',
                '-CAfile', trusted_ca_filename,
                '-untrusted', untrusted_cas_filename,
                nom_fichier_tmp,
            ]

            self._logger.debug("Commande openssl: %s" % str(commande_openssl))

            process_output = subprocess.run(commande_openssl, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Travail avec le certificat termine, il est supprime.
        os.unlink(nom_fichier_tmp)

        resultat = process_output.returncode
        output_txt = '%s\n%s' % (process_output.stderr.decode('utf8'), process_output.stdout.decode('utf8'))

        if resultat != 0:
            message = 'Certificat invalide. Output openssl: %s' % output_txt
            self._logger.debug(message)
            raise CertificatInvalide(message, key_subject_identifier=enveloppe.fingerprint_ascii)

        enveloppe.set_est_verifie(True)

        return resultat == 0, output_txt

    def charger_fiche(self, fiche, certs_signataires: list = None):
        """
        Charge et valide des certificats provenant d'une fiche de MilleGrille tierce
        """
        certificats = list()  # Accumuler tous les certificats pour les re-emettre dans la MilleGrille
        idmg_entete = fiche[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]

        # Charger et valider le certificat racine
        certificat_racine = fiche['certificat_racine']
        enveloppe_racine = EnveloppeCertificat(certificat_pem=certificat_racine)
        if enveloppe_racine.idmg != idmg_entete:
            raise CertificatInvalide("Racine %s invalide, fiche contient idmg=%s" % (enveloppe_racine.idmg, idmg_entete))

        self._ajouter_racine(enveloppe_racine)
        certificats.append(enveloppe_racine)

        # Charger et valider les certificats intermediaires
        certificats_intermediaires = fiche['certificats_intermediaires']
        for cert in certificats_intermediaires:
            enveloppe_intermediaire = EnveloppeCertificat(certificat_pem=cert)
            if enveloppe_intermediaire.subject_organization_name == idmg_entete:
                self._ajouter_untrusted_ca(enveloppe_intermediaire)
                certificats.append(enveloppe_intermediaire)
            else:
                self._logger.warning("Certificat intermediaire invalide, idmg=%s plutot que %s" % (enveloppe_intermediaire.idmg, idmg_entete))

        # Charger et valider les autres certificats (leaf)
        certificats_additionnels = fiche.get('certificats_additionnels')
        certificat_correspondance = fiche.get('certificat')

        cert_a_valider = list()
        if certificats_additionnels is not None:
            cert_a_valider.extend(certificats_additionnels)
        if certificat_correspondance is not None:
            cert_a_valider.append(certificat_correspondance)
        if certs_signataires is not None:
            cert_a_valider.extend(certs_signataires)

        for cert in cert_a_valider:
            enveloppe_leaf = EnveloppeCertificat(certificat_pem=cert)
            if enveloppe_leaf.subject_organization_name == idmg_entete and not enveloppe_leaf.is_CA:
                self.verifier_chaine(enveloppe_leaf)
                certificats.append(enveloppe_leaf)
            else:
                self._logger.warning("Certificat leaf invalide, CA=%s, idmg=%s (source: %s)" % (
                    enveloppe_leaf.is_CA, enveloppe_leaf.idmg, idmg_entete))

        # Retourne les certificats qui sont valides
        return certificats

    def close(self):
        # Supprimer tous les certificats mis sur le disque
        shutil.rmtree(self.__workdir, ignore_errors=True)


class EncryptionHelper:

    def __init__(self, enveloppe_certificat: EnveloppeCertificat):
        self.__enveloppe_certificat = enveloppe_certificat
        self.__json_helper = JSONHelper()

    def __ouvrir_cipher(self, cert):
        password = secrets.token_bytes(32)  # AES-256 = 32 bytes
        cle_publique = cert.public_key()
        password_crypte = cle_publique.encrypt(
            password,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        iv = secrets.token_bytes(16)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv), backend=backend)

        return password_crypte, iv, cipher

    def crypter_dict(self, contenu_dict: dict):

        cert = self.__enveloppe_certificat.certificat
        password_crypte, iv, cipher = self.__ouvrir_cipher(cert)

        # Crypter contenu du dictionnaire (cle symmetrique)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(ConstantesSecurityPki.SYMETRIC_PADDING).padder()
        dict_bytes = self.__json_helper.dict_vers_json(contenu_dict, DateFormatEncoder).encode('utf-8')

        # Inserer IV dans les premiers 16 bytes - pas vraiment le choix, c'est l'algo:
        # https://stackoverflow.com/questions/26928012/wrong-16-bytes-in-decryption-using-aes
        dict_bytes = iv + dict_bytes
        dict_padded = padder.update(dict_bytes) + padder.finalize()
        dict_crypte_bytes = encryptor.update(dict_padded) + encryptor.finalize()
        dict_crypte_strbytes = base64.b64encode(dict_crypte_bytes)
        dict_crypte_str = dict_crypte_strbytes.decode('utf-8')

        return dict_crypte_str, password_crypte, iv


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

        exchange = self.contexte.configuration.exchange_noeuds

        self.__logger.debug("Transmission certificat PKI a l'initialisation")
        enveloppe = self.transmettre_certificat()
        fingerprint = enveloppe.fingerprint_ascii
        routing_key = '%s.%s' % (ConstantesSecurityPki.EVENEMENT_REQUETE, fingerprint)

        self.__channel.queue_bind(queue=nom_queue, exchange=exchange, routing_key=routing_key, callback=None)
        self.__channel.basic_consume(self.callbackAvecAck, queue=nom_queue, no_ack=False)
        self.__routing_cert = routing_key

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def transmettre_certificat(self):
        enveloppe = self.enveloppe_certificat_courant

        message_evenement = ConstantesSecurityPki.DOCUMENT_EVENEMENT_CERTIFICAT.copy()
        message_evenement[ConstantesSecurityPki.LIBELLE_FINGERPRINT] = enveloppe.fingerprint_ascii
        message_evenement[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM] = str(
            enveloppe.certificat.public_bytes(serialization.Encoding.PEM), 'utf-8'
        )

        routing = '%s.%s' % (ConstantesSecurityPki.EVENEMENT_CERTIFICAT, enveloppe.fingerprint_ascii)
        self.contexte.message_dao.transmettre_message(
            message_evenement, routing, channel=self.__channel
        )
        self.contexte.message_dao.transmettre_message_noeuds(
            message_evenement, routing
        )

        return enveloppe

    def traiter_message(self, ch, method, properties, body):
        # Implementer la lecture de messages, specialement pour transmettre un certificat manquant
        routing_key = method.routing_key
        if routing_key == self.__routing_cert:
            # Transmettre notre certificat
            self.transmettre_certificat()
        else:
            raise Exception("Routing non gere: %s" % routing_key)


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

    @property
    def key_subject_identifier(self):
        return self._key_subject_identifier

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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.name import NameOID

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.dao.DocumentDAO import MongoJSONEncoder


class ConstantesSecurityPki:

    DELIM_DEBUT_CERTIFICATS = '-----BEGIN CERTIFICATE-----'
    COLLECTION_NOM = 'millegrilles.domaines.Pki/documents'

    LIBELLE_CERTIFICAT_PEM = 'certificat_pem'
    LIBELLE_FINGERPRINT = 'fingerprint'

    EVENEMENT_CERTIFICAT = 'pki.certificat'  # Indique que c'est un evenement avec un certificat (reference)
    EVENEMENT_REQUETE = 'pki.requete'  # Indique que c'est une requete pour trouver un certificat par fingerprint

    REGLE_LIMITE_CHAINE = 4  # Longeur maximale de la chaine de certificats

    # Document utilise pour publier un certificat
    DOCUMENT_EVENEMENT_CERTIFICAT = {
        Constantes.EVENEMENT_MESSAGE_EVENEMENT: EVENEMENT_CERTIFICAT,
        LIBELLE_FINGERPRINT: None,
        LIBELLE_CERTIFICAT_PEM: None
    }


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

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def fingerprint_ascii(self):
        return str(binascii.hexlify(self._fingerprint), 'utf-8')

    @property
    def certificat(self):
        return self._certificat

    @property
    def certificat_pem(self):
        return str(self.certificat.public_bytes(serialization.Encoding.PEM), 'utf-8')

    @property
    def subject_organizational_unit_name(self):
        return self._certificat.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value

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

    @property
    def authority_key_identifier(self):
        authorityKeyIdentifier = self.certificat.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        key_id = bytes.hex(authorityKeyIdentifier.value.key_identifier)
        self._logger.debug("Certificate issuer: %s" % key_id)
        return key_id

    @property
    def is_rootCA(self):
        return self.is_CA and self.certificat.issuer == self.certificat.subject

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
        message_json = json.dumps(
            transaction_temp,
            ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
            sort_keys=True,
            separators=(',', ':'),
            cls=MongoJSONEncoder
        )
        message_bytes = bytes(message_json, 'utf-8')

        return message_bytes

    def verifier_certificat(self, dict_message):
        # self._verifier_usage()  # Deja fait au chargement
        self._verifier_cn(dict_message)

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

    def _verifier_cn(self, dict_message: dict, enveloppe: EnveloppeCertificat = None):
        if enveloppe is not None:
            sujet = enveloppe.certificat.subject
        else:
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

    def hacher_contenu(self, dict_message):
        """
        Produit un hash SHA-2 256bits du contenu d'un message. Exclue l'en-tete.
        :param dict_message:
        :return:
        """
        dict_message_effectif = dict_message.copy()
        del dict_message_effectif['en-tete']  # Retirer l'en-tete, on ne fait que hacher le contenu du dict
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
    def enveloppe_certificat_courant(self):
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

        self.verifier_certificat(dict_message_effectif)  # Verifier que l'entete correspond au certificat

        # Ajouter information du certification dans l'en_tete
        fingerprint_cert = self._enveloppe.fingerprint_ascii
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
                mgf=padding.MGF1(self._sign_hash_function()),
                salt_length=padding.PSS.MAX_LENGTH
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

        enveloppe_certificat = self._identifier_certificat(dict_message)
        self._logger.debug("Certificat utilise pour verification signature message: %s" % enveloppe_certificat.fingerprint_ascii)
        self._verifier_cn(dict_message, enveloppe=enveloppe_certificat)
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
            padding.PSS(
                mgf=padding.MGF1(self._sign_hash_function()),
                salt_length=padding.PSS.MAX_LENGTH
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

        self.__untrusted_CAs_filename = None
        self.__untrusted_CAs_writer = None

        self._initialiser_cas()

    def charger_certificat(self, fichier=None, fingerprint=None):
        # Tenter de charger a partir d'une copie locale
        enveloppe = None
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

        elif os.path.isfile(fichier):
            certificat = self._charger_pem(fichier)

            if certificat is not None:
                enveloppe = EnveloppeCertificat(certificat)

        # Conserver l'enveloppe dans le cache
        if enveloppe is not None:

            if not enveloppe.est_verifie:
                # Verifier la chaine de ce certificat
                if enveloppe.is_CA:
                    # Ajouter dans le fichier temp des untrusted CAs pour openssl
                    # Note: si le certificat est invalide, c'est possiblement parce que les autorites ne
                    # sont pas chargees en ordre. On le conserve quand meme.
                    if enveloppe.fingerprint_ascii not in self._liste_CAs_connus:
                        self._logger.debug("Conserver cert CA dans untrusted: %s" % enveloppe.fingerprint_ascii)
                        self._ajouter_untrusted_ca(enveloppe)

                self.verifier_chaine(enveloppe)
                self._cache_certificats_fingerprint[enveloppe.fingerprint_ascii] = enveloppe

        else:
            raise ValueError("Certificat ne peut pas etre charge")

        return enveloppe

    def _ajouter_untrusted_ca(self, enveloppe: EnveloppeCertificat):

        if self.__untrusted_CAs_writer is None:
            # Ouvrir un fichier pour ecrire les untrusted CAs. Le fichier reste ouvert pour eviter qu'il soit
            # modifie ou efface par un processus tiers.
            workdir = self.configuration.pki_workdir
            self.__untrusted_CAs_filename = tempfile.mktemp(prefix='untrusted.', suffix='.cert.pem', dir=workdir)
            self.__untrusted_CAs_writer = open(self.__untrusted_CAs_filename, 'w')

        self.__untrusted_CAs_writer.write(enveloppe.certificat_pem)
        self.__untrusted_CAs_writer.flush()

    def _initialiser_cas(self):
        """
        Initialise la liste des CA connus et ouvre un fichier pour les untrusted CAs.
        :return:
        """
        # Charger le root CAs. On garde les fingerprints en memoire pour indiquer qu'il
        # n'est pas necessaire de les ajouter au fichier untrusted CAs.

        pass

    def verifier_chaine(self, enveloppe: EnveloppeCertificat):
        """
        Utilise les root CA et untrusted CAs pour verifier la chaine du certificat
        :return: True si le certificat est valide selon la chaine de certification, date, etc (openssl).
        """
        workdir = self.configuration.pki_workdir
        nom_fichier_tmp = tempfile.mktemp(suffix='.cert.pem', dir=workdir)
        with open(nom_fichier_tmp, 'w') as output_cert_file :
            output_cert_file.write(enveloppe.certificat_pem)

            # Flush le contenu, mais on garde le write lock sur le fichier pour eviter
            # qu'il soit altere par un autre processus.
            output_cert_file.flush()

            root_ca_path = self.configuration.pki_cafile
            self._logger.debug("Cert CA: %s, untrusted: %s" % (root_ca_path, self.__untrusted_CAs_filename))

            commande_openssl = [
                'openssl', 'verify',
                '-CAfile', root_ca_path,
            ]
            if self.__untrusted_CAs_writer is not None:
                commande_openssl.extend(['-untrusted', self.__untrusted_CAs_filename])
            commande_openssl.append(nom_fichier_tmp)

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

    def close(self):
        if self.__untrusted_CAs_writer is not None:
            self.__untrusted_CAs_writer.close()
            os.unlink(self.__untrusted_CAs_filename)


class GestionnaireEvenementsCertificat(UtilCertificats, BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte=contexte)

    def initialiser(self, channel=None):
        super().initialiser()

        if channel is not None:
            self.transmettre_certificat(channel)

    def transmettre_certificat(self, channel=None):
        enveloppe = self.enveloppe_certificat_courant

        message_evenement = ConstantesSecurityPki.DOCUMENT_EVENEMENT_CERTIFICAT.copy()
        message_evenement[ConstantesSecurityPki.LIBELLE_FINGERPRINT] = enveloppe.fingerprint_ascii
        message_evenement[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM] = str(
            enveloppe.certificat.public_bytes(serialization.Encoding.PEM), 'utf-8'
        )

        routing = '%s.%s' % (ConstantesSecurityPki.EVENEMENT_CERTIFICAT, enveloppe.fingerprint_ascii)
        self.contexte.message_dao.transmettre_message(
            message_evenement, routing, channel=channel
        )

    def traiter_message(self, ch, method, properties, body):
        # Implementer la lecture de messages, specialement pour transmettre un certificat manquant
        pass


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

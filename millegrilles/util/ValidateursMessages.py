# Validateurs de messages (transactions, documents, commandes, etc.)
import datetime
import json
import logging
import pytz

from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, asymmetric
from typing import Union

from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.util.ValidateursPki import ValidateurCertificatRequete
from millegrilles.SecuritePKI import EnveloppeCertificat, HachageInvalide
from millegrilles.util.JSONMessageEncoders import DateFormatEncoder


class ValidateurMessage:
    """
    Validateur de messages. Verifie le hachage et la signature.
    """

    def __init__(self, contexte: ContexteRessourcesMilleGrilles):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__validateur = ValidateurCertificatRequete(contexte)
        self.__hash_function = hashes.SHA256
        self.__signature_hash_function = hashes.SHA512

    def verifier(self, message: Union[bytes, str, dict]) -> EnveloppeCertificat:
        if isinstance(message, bytes):
            dict_message = json.loads(message.decode('utf-8'))
        elif isinstance(message, str):
            dict_message = json.loads(message)
        elif isinstance(message, dict):
            dict_message = message.copy()
        else:
            raise TypeError("La transaction doit etre en format bytes, str ou dict")

        signature = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE]

        # Preparer le message pour verification du hachage et de la signature
        message_nettoye = ValidateurMessage.__preparer_message(dict_message)

        self.__verifier_hachage(message_nettoye)
        enveloppe_certificat = self.__verifier_signature(message_nettoye, signature)

        return enveloppe_certificat

    def __verifier_hachage(self, message: dict):
        message_sans_entete = message.copy()
        del message_sans_entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        message_bytes = json.dumps(message_sans_entete).encode('utf-8')

        entete = message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        hachage = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE]

        fonction_hachage = self.__hash_function()
        digest = hashes.Hash(fonction_hachage, backend=default_backend())

        digest.update(message_bytes)
        resultat_digest = digest.finalize()
        digest_base64 = hachage.name + '_b64:' + b64encode(resultat_digest).decode('utf-8')

        self.__logger.debug("Resultat hash contenu: %s" % digest_base64)
        if hachage != digest_base64:
            raise HachageInvalide("Le hachage %s ne correspond pas au contenu recu %s" % (
                hachage, digest_base64
            ))
        self.__logger.debug("Hachage de la transaction est OK: %s" % digest_base64)

    def __verifier_signature(self, message: dict, signature: str, utiliser_date_message=False) -> EnveloppeCertificat:
        enveloppe_certificat = self.__valider_certificat_message(message, utiliser_date_message)

        # Le certificat est valide. Valider la signature du message.
        signature_bytes = b64decode(signature)
        message_bytes = json.dumps(message).encode('utf-8')

        certificat = enveloppe_certificat.certificat
        cle_publique = certificat.public_key()
        cle_publique.verify(
            signature_bytes,
            message_bytes,
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(self.__signature_hash_function()),
                salt_length=64  # max supporte sur iPhone asymmetric.padding.PSS.MAX_LENGTH
            ),
            self.__signature_hash_function()
        )

        # Signature OK, aucune exception n'a ete lancee

        return enveloppe_certificat

    def __valider_certificat_message(self, message, utiliser_date_message):
        entete = message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        idmg_message = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]
        if utiliser_date_message:
            estampille = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
            date_reference = datetime.datetime.fromtimestamp(estampille, tz=pytz.UTC)
        else:
            date_reference = None

        # Tenter d'extraire un certificat inclus dans le message - il sera utilise pour la validation
        certificats_inline = \
            message.get('_certificats') or \
            message.get('_certificat') or \
            message.get('certificat')

        # Valider le certificat
        if certificats_inline is not None:
            enveloppe_certificat = self.__validateur.valider(
                certificats_inline, date_reference=date_reference, idmg=idmg_message)
        else:
            entete = message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
            fingerprint = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT]
            enveloppe_certificat = self.__validateur.valider_fingerprint(
                fingerprint, date_reference=date_reference, idmg=idmg_message)

        return enveloppe_certificat

    @staticmethod
    def __preparer_message(message: dict) -> dict:
        message_nettoye = dict()
        for key, value in message.items():
            if not key.startswith('_'):
                message_nettoye[key] = value

        # Premiere passe, converti les dates. Les nombre floats sont incorrects.
        message_str = json.dumps(
            message_nettoye,
            ensure_ascii=False,   # S'assurer de supporter tous le range UTF-8
            cls=DateFormatEncoder
        )

        # HACK - Fix pour le decodage des float qui ne doivent pas finir par .0 (e.g. 100.0 doit etre 100)
        message_nettoye = json.loads(message_str, parse_float=ValidateurMessage.__parse_float)

        return message_nettoye

    @staticmethod
    def __parse_float(f: str):
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

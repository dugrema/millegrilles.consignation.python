import datetime
import json
import logging
import multibase
import uuid

from typing import Union

from millegrilles import Constantes
from millegrilles.SecuritePKI import SignateurTransaction, UtilCertificats
from millegrilles.util.Hachage import hacher
from millegrilles.util.X509Certificate import EnveloppeCleCert


class SignateurTransactionSimple:
    """ Signe une transaction avec clecert. """

    def __init__(self, clecert: EnveloppeCleCert):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.__clecert = clecert

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
        fingerprint_cert = self.__clecert.fingerprint
        # self._logger.debug("Fingerprint: %s" % fingerprint_cert)
        en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT] = fingerprint_cert

        signature = self._produire_signature(dict_message_effectif)
        dict_message_effectif[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE] = signature

        return dict_message_effectif

    def _produire_signature(self, dict_message):
        # message_bytes = self.preparer_transaction_bytes(dict_message)
        message_bytes = UtilCertificats.preparer_message_bytes(dict_message)
        self._logger.debug("Message en format json: %s" % message_bytes)
        signature = self.__clecert.signer(message_bytes)
        # signature_texte_utf8 = str(base64.b64encode(signature), 'utf-8')

        VERSION_SIGNATURE = 1
        signature = bytes([VERSION_SIGNATURE]) + signature

        signature_encodee = multibase.encode('base64', signature).decode('utf-8')
        self._logger.debug("Signature: %s" % signature_encodee)

        return signature_encodee

    @property
    def chaine_certs(self) -> list:
        return self.__clecert.chaine


class FormatteurMessageMilleGrilles:
    """
    Classe qui permet de creer l'entete de messages d'une MilleGrille et de signer les messages.
    Supporte aussi une contre-signature pour emission vers une MilleGrille tierce.
    """

    def __init__(self, idmg: str, signateur_transactions: Union[SignateurTransaction, SignateurTransactionSimple]):
        """
        :param idmg: MilleGrille correspondant au signateur de transactions
        :param signateur_transactions: Signateur de transactions pour la MilleGrille
        :param contresignateur_transactions: Contre-signateur (e.g. pour un connecteur inter-MilleGrilles)
        """
        self.__idmg = idmg
        self.__signateur_transactions = signateur_transactions
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def signer_message(self,
                       message: dict,
                       domaine: str = None,
                       version: int = Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6,
                       idmg_destination: str = None,
                       ajouter_chaine_certs = False,
                       action: str = None,
                       partition: str = None) -> (dict, str):
        """
        Formatte un message en ajoutant l'entete et en le signant.

        :param message: Message a signer
        :param domaine: Domaine a ajouter dans l'entete
        :param version: Version du message (depend du domaine)
        :param idmg_destination: Optionnel, idmg destination pour le message.
        :return: Message signe
        """

        # Ajouter identificateur unique et temps de la transaction
        uuid_transaction = uuid.uuid1()

        meta = dict()
        meta[Constantes.CONFIG_IDMG] = self.__idmg
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID] = "%s" % uuid_transaction
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE] = int(datetime.datetime.utcnow().timestamp())
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION] = version
        if domaine is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE] = domaine
        if action is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_ACTION] = action
        if partition is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_PARTITION] = partition
        if idmg_destination is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG_DESTINATION] = idmg_destination

        enveloppe = message.copy()
        enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION] = meta
        try:
            del enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        except KeyError:
            pass  # L'entete n'existait pas

        # Nettoyer le message, serialiser pour eliminer tous les objets
        enveloppe_bytes = UtilCertificats.preparer_message_bytes(enveloppe)
        # enveloppe_bytes = self.__signateur_transactions.preparer_transaction_bytes(enveloppe)

        # Hacher le contenu avec SHA2-256 et signer le message avec le certificat du noeud
        # meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE] = self.__signateur_transactions.hacher_bytes(enveloppe_bytes)
        self.__logger.debug("Message a hacher : %s" % enveloppe_bytes.decode('utf-8'))
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE] = hacher(
            enveloppe_bytes, hashing_code='sha2-256', encoding='base64')

        # Recuperer le dict de message (deserialiser), ajouter l'entete pour signer le message
        enveloppe = json.loads(enveloppe_bytes)
        enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE] = meta

        message_signe = self.__signateur_transactions.signer(enveloppe)

        if ajouter_chaine_certs:
            # Ajouter un element _certificats = [cert, inter, millegrilles]
            message_signe[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS] = \
                self.__signateur_transactions.chaine_certs

        return message_signe, uuid_transaction

    @property
    def chaine_certificat(self):
        return self.__signateur_transactions.chaine_certs


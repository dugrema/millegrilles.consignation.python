from millegrilles import Constantes
from millegrilles.SecuritePKI import SignateurTransaction

import uuid
import datetime
import json


class FormatteurMessageMilleGrilles:
    """
    Classe qui permet de creer l'entete de messages d'une MilleGrille et de signer les messages.
    Supporte aussi une contre-signature pour emission vers une MilleGrille tierce.
    """

    def __init__(self, idmg: str, signateur_transactions: SignateurTransaction,
                 contresignateur_transactions: SignateurTransaction = None):
        """
        :param idmg: MilleGrille correspondant au signateur de transactions
        :param signateur_transactions: Signateur de transactions pour la MilleGrille
        :param contresignateur_transactions: Contre-signateur (e.g. pour un connecteur inter-MilleGrilles)
        """
        self.__idmg = idmg
        self.__signateur_transactions = signateur_transactions
        self.__contresignateur_transactions = contresignateur_transactions

        with open(signateur_transactions.configuration.mq_certfile) as certs:
            cert = self.__signateur_transactions.certificat
            self.__chaine_certificats = [

            ]


    def signer_message(self,
                       message: dict,
                       domaine: str = None,
                       version: int = Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6,
                       idmg_destination: str = None,
                       ajouter_chaine_certs = False) -> (dict, str):
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
        if idmg_destination is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG_DESTINATION] = idmg_destination

        enveloppe = message.copy()
        enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION] = meta
        try:
            del enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        except KeyError:
            pass  # L'entete n'existait pas

        # Nettoyer le message, serialiser pour eliminer tous les objets
        enveloppe_bytes = self.__signateur_transactions.preparer_transaction_bytes(enveloppe)

        # Hacher le contenu avec SHA2-256 et signer le message avec le certificat du noeud
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE] = self.__signateur_transactions.hacher_bytes(enveloppe_bytes)

        # Recuperer le dict de message (deserialiser), ajouter l'entete pour signer le message
        enveloppe = json.loads(enveloppe_bytes)
        enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE] = meta

        message_signe = self.__signateur_transactions.signer(enveloppe)

        if ajouter_chaine_certs:
            # Ajouter un element _certificats = [cert, inter, millegrilles]
            message_signe['_certificats'] = self.__signateur_transactions.chaine_certs

        return message_signe, uuid_transaction

    def contresigner_message(self, message: dict):
        """
        Ajouter une signature avec un certificat de MilleGrille tierce.
        :param message:
        :return:
        """
        message_contresigne = self.__contresignateur_transactions.signer(message)
        return message_contresigne

    @property
    def chaine_certificat(self):
        return self.__signateur_transactions.chaine_certs

import uuid
import datetime
import re

from millegrilles import Constantes
from millegrilles.util.JSONMessageEncoders import DateFormatEncoder


class GenerateurTransaction:
    """
    Generateur de transactions, requetes et reponses vers RabbitMQ.
    """

    def __init__(self, contexte, encodeur_json=DateFormatEncoder):
        self.encodeur_json = encodeur_json
        self._contexte = contexte

    def preparer_enveloppe(self, message_dict, domaine=None, version=Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6,
                           idmg_destination: str = None):

        # Identifier usager du systeme, nom de domaine
        signateur_transactions = self._contexte.signateur_transactions

        # common_name = signateur_transactions.enveloppe_certificat_courant.subject_common_name
        # identificateur_systeme = '%s/%s@%s' % (getpass.getuser(), socket.getfqdn(), common_name)

        # Ajouter identificateur unique et temps de la transaction
        uuid_transaction = uuid.uuid1()

        meta = dict()
        meta[Constantes.CONFIG_IDMG] = self._contexte.idmg
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID] = "%s" % uuid_transaction
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE] = int(datetime.datetime.utcnow().timestamp())
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION] = version
        if domaine is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE] = domaine
        if idmg_destination is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG_DESTINATION] = idmg_destination

        enveloppe = message_dict.copy()
        enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION] = meta

        # Hacher le contenu avec SHA2-256 et signer le message avec le certificat du noeud
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE] = signateur_transactions.hacher_contenu(enveloppe)
        message_signe = signateur_transactions.signer(enveloppe)

        return message_signe

    def soumettre_transaction(self, message_dict, domaine=None,
                              reply_to=None, correlation_id=None,
                              version=Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6,
                              idmg_destination: str = None):
        """
        Transmet un message. La connexion doit etre ouverte.

        :param message_dict: Dictionnaire du contenu (payload) du message.
        :param domaine: Domaine du message. Utilise pour le routage de la transaction apres persistance.
        :param reply_to:
        :param correlation_id:
        :param version:
        :param idmg_destination: MilleGrille destination
        :returns: UUID de la transaction. Permet de retracer la transaction dans MilleGrilles une fois persistee.
        """

        # Preparer la structure du message reconnue par MilleGrilles
        enveloppe = self.preparer_enveloppe(message_dict, domaine, version=version, idmg_destination=idmg_destination)

        # Extraire le UUID pour le retourner a l'invoqueur de la methode. Utilise pour retracer une soumission.
        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        self._contexte.message_dao.transmettre_nouvelle_transaction(enveloppe, reply_to, correlation_id)

        return uuid_transaction

    def relayer_transaction_vers_tiers(self, transaction: dict, reply_to: str = None, correlation_id: str = None):
        """
        Tente d'acheminer une transaction vers une MilleGrille tierce.

        :param transaction:
        :param reply_to:
        :param correlation_id:
        """
        idmg_destination = transaction[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG_DESTINATION]

        self._contexte.message_dao.transmettre_message_intermillegrilles(
            transaction, idmg_destination, encoding=self.encodeur_json,
            reply_to=reply_to, correlation_id=correlation_id)

    def transmettre_requete(self, message_dict, domaine, correlation_id, reply_to=None, domaine_direct=False,
                            idmg_destination: str = None):
        """
        Transmet une requete au backend de MilleGrilles. La requete va etre vu par un des workers du domaine. La
        reponse va etre transmise vers la "message_dao.queue_reponse", et le correlation_id permet de savoir a
        quelle requete la reponse correspond.
        :param message_dict:
        :param domaine: Domaine qui doit traiter la requete - doit correspondre a a une routing key.
        :param correlation_id: Numero utilise pour faire correspondre la reponse.
        :param reply_to:
        :param domaine_direct:
        :param idmg_destination: MilleGrille destination pour la reponse
        :return:
        """

        if reply_to is None:
            reply_to = self._contexte.message_dao.queue_reponse

        enveloppe = message_dict.copy()
        enveloppe = self.preparer_enveloppe(enveloppe, 'requete.%s' % domaine, idmg_destination=idmg_destination)
        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        if domaine_direct:
            routing_key = domaine
        else:
            routing_key = 'requete.%s' % domaine

        if idmg_destination is None:
            self._contexte.message_dao.transmettre_message_noeuds(
                enveloppe, routing_key, encoding=self.encodeur_json,
                reply_to=reply_to, correlation_id=correlation_id)
        else:
            self._contexte.message_dao.transmettre_message_intermillegrilles(
                enveloppe, idmg_destination, encoding=self.encodeur_json,
                reply_to=reply_to, correlation_id=correlation_id)

        return uuid_transaction

    def transmettre_reponse(self, message_dict, replying_to, correlation_id, idmg_destination: str = None):
        """
        Transmet une reponse a une requete. La reponse va directement sur la queue replying_to (pas de topic).
        :param message_dict: Message de reponse
        :param replying_to: Nom de la Q sur laquelle la reponse va etre transmise (reply-to de la requete)
        :param correlation_id: Numero de correlation fourni dans la requete.
        :param idmg_destination: MilleGrille destination pour la reponse
        :return:
        """

        enveloppe = self.preparer_enveloppe(message_dict, idmg_destination=idmg_destination)

        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        self._contexte.message_dao.transmettre_reponse(
            enveloppe, replying_to, correlation_id, encoding=self.encodeur_json)

        return uuid_transaction

    def transmettre_commande(self, commande_dict, routing_key, channel=None, encoding=DateFormatEncoder,
                             exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS, idmg_destination: str = None):

        enveloppe = self.preparer_enveloppe(commande_dict, idmg_destination=idmg_destination)

        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        self._contexte.message_dao.transmettre_commande(enveloppe, routing_key,
                                                        channel=channel, encoding=encoding, exchange=exchange)

        return uuid_transaction

    def emettre_commande_noeuds(self, message_dict, routing_key, idmg_destination: str = None):
        """
        Transmet une reponse a une requete. La reponse va directement sur la queue replying_to (pas de topic).
        :param message_dict: Message de reponse
        :param routing_key:
        :param idmg_destination: MilleGrille destination
        :return:
        """

        enveloppe = self.preparer_enveloppe(message_dict, idmg_destination=idmg_destination)

        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        self._contexte.message_dao.transmettre_message_noeuds(
            message_dict=enveloppe, routing_key=routing_key, encoding=self.encodeur_json)

        return uuid_transaction

    def emettre_message(self, message_dict, routing_key):

        enveloppe = self.preparer_enveloppe(message_dict)

        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        self._contexte.message_dao.transmettre_message_noeuds(
            message_dict=enveloppe, routing_key=routing_key
        )

        return uuid_transaction

    def relayer_transaction(self, enveloppe):

        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        self._contexte.message_dao.transmettre_message_noeuds(
            message_dict=enveloppe, routing_key='transaction.nouvelle'
        )

        return uuid_transaction

class TransactionOperations:

    def __init__(self):
        pass

    def enlever_champsmeta(self, transaction, champs_a_exclure=None):
        copie = transaction.copy()

        if champs_a_exclure is not None:
            for champ in champs_a_exclure:
                if copie.get(champ) is not None:
                    del copie[champ]

        regex_ignorer = re.compile('^_.+')
        for cle in transaction.keys():
            m = regex_ignorer.match(cle)
            if m:
                del copie[cle]

        return copie

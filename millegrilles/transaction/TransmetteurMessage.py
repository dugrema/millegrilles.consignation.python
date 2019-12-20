import logging

from pika.channel import Channel
from pika import BasicProperties

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import ConnexionWrapper
from millegrilles.util.JSONMessageEncoders import DateFormatEncoder, JSONHelper
from millegrilles.transaction.FormatteurMessage import FormatteurMessageMilleGrilles
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles


class TransmetteurMessageMilleGrilles:
    """
    Formatte et transmet des messages.
    """

    __json_helper = JSONHelper()

    def __init__(self, contexte: ContexteRessourcesMilleGrilles, channel: Channel,
                 connexion_wrapper: ConnexionWrapper = None, encodeur_json=DateFormatEncoder):

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__contexte = contexte
        self.__channel = channel
        self.__connexion_wrapper = connexion_wrapper
        self.__channel_lock = None

        if connexion_wrapper is not None:
            self.__channel_lock = connexion_wrapper.publish_lock

        self.encodeur_json = encodeur_json
        self.__formatteur_message = FormatteurMessageMilleGrilles(
            self.__contexte.idmg, self.__contexte.signateur_transactions)

    def emettre_message_prive(self, message: dict, routing_key: str,
                              version: int = Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6):

        message_signe = self.__formatteur_message.signer_message(message, routing_key, version=version)

        uuid_transaction = message_signe[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        self._publish_prive(message_signe, routing_key)

        return uuid_transaction, message_signe

    def _publish_direct(self, message, queue_name,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = ''  # Echange par defaut
        self.__publish(message, queue_name, echange, delivery_mode_v, encoding, reply_to, correlation_id)

    def _publish_public(self, message, routing_key,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = self.__contexte.configuration.exchange_public
        self.__publish(message, routing_key, echange, delivery_mode_v, encoding, reply_to, correlation_id)

    def _publish_prive(self, message, routing_key, delivery_mode_v=1,
                       encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = self.__contexte.configuration.exchange_prive
        self.__publish(message, routing_key, echange, delivery_mode_v, encoding, reply_to, correlation_id)

    def _publish_protege(self, message, routing_key,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = self.__contexte.configuration.exchange_noeuds
        self.__publish(message, routing_key, echange, delivery_mode_v, encoding, reply_to, correlation_id)

    def _publish_secure(self, message, routing_key,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = self.__contexte.configuration.exchange_middleware
        self.__publish(message, routing_key, echange, delivery_mode_v, encoding, reply_to, correlation_id)

    def __publish(self, message, routing_key, echange,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):

        properties = BasicProperties(delivery_mode=delivery_mode_v)
        if reply_to is not None:
            properties.reply_to = reply_to
        if correlation_id is not None:
            properties.correlation_id = correlation_id

        message_utf8 = TransmetteurMessageMilleGrilles.__json_helper.dict_vers_json(message, encoding)
        with self.__channel_lock:
            self.__channel.basic_publish(
                exchange=echange,
                routing_key=routing_key,
                body=message_utf8,
                properties=properties,
                mandatory=True)

        # Utiliser pubdog pour la connexion publishing par defaut
        if self.__connexion_wrapper is not None:
            self.__connexion_wrapper.publish_watch()

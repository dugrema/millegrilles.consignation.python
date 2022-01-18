import logging

from pika.spec import Basic
from pika import BasicProperties
from threading import Lock, Event, Thread

from millegrilles import Constantes
from millegrilles.util.JSONMessageEncoders import DateFormatEncoder, JSONHelper
from millegrilles.transaction.FormatteurMessage import FormatteurMessageMilleGrilles
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles


class TransmetteurMessageMilleGrilles:
    """
    Formatte et transmet des messages.
    """

    __json_helper = JSONHelper()

    def __init__(self, contexte: ContexteRessourcesMilleGrilles,
                 publish_lock: Lock = Lock(), encodeur_json=DateFormatEncoder,
                 callback_on_channel_open: classmethod = None,
                 callback_enter_error_state: classmethod = None,
                 stop_event: Event = Event(),
                 descriptif: str = "TM"):

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__contexte = contexte
        self.__channel = None
        self.__channel_lock = publish_lock
        self.__callback_on_channel_open = callback_on_channel_open

        self.__callback_enter_error_state = callback_enter_error_state
        self.__stop_event = stop_event

        self.descriptif = descriptif

        self.encodeur_json = encodeur_json
        self.__formatteur_message = FormatteurMessageMilleGrilles(
            self.__contexte.idmg, self.__contexte.signateur_transactions)

        self.__published = False
        self.__publish_confirm_event = Event()
        self.__thread_publishing_watchdog = None

    def close(self):
        self.__stop_event.set()

    def on_channel_open(self, channel):
        """
        Callback pour ouverture du channel de transmission
        :param channel:
        :return:
        """
        self.__logger.debug("MQ Channel ouvert")
        self.__channel = channel

        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        channel.confirm_delivery(self.__confirm_delivery)
        channel.add_on_return_callback(self.__on_return)

        if self.__callback_on_channel_open is not None:
            self.__callback_on_channel_open(channel)

    def on_channel_close(self, channel=None, code=None, reason=None):
        """
        Callback pour fermeture du channel de transmission
        :param channel:
        :param code:
        :param reason:
        :return:
        """
        self.__logger.debug("MQ Channel ferme")
        self.__channel = None

    def __on_return(self, channel, method, properties, body):
        self.__logger.debug("Return callback %s (channel: %s, properties: %s):\n%s" % (
            str(method), str(channel), str(properties), str(body)))
        self.__publish_confirm_event.set()

    def __confirm_delivery(self, frame):
        self.__logger.debug("Delivery: %s" % str(frame))
        confirmation_type = frame.method.NAME.split('.')[1].lower()
        if confirmation_type == 'ack':
            self.__publish_confirm_event.set()
        elif confirmation_type == 'nack':
            self.__logger.error("Delivery NACK")
            if self.__callback_enter_error_state is not None:
                self.__callback_enter_error_state()

    def is_channel_open(self):
        return self.__channel is not None

    def emettre_message_prive(self, message: dict, routing_key: str,
                              version: int = Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6):

        message_signe, uuid_transaction = self.__formatteur_message.signer_message(
            message, routing_key, version=version)
        self._publish_prive(message_signe, routing_key)
        return uuid_transaction, message_signe

    def emettre_message_public(self, message: dict, routing_key: str,
                               version: int = Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6):
        """
        Emet un message sur l'echange public.

        :param message:
        :param routing_key:
        :param version:
        :return:
        """

        message_signe, uuid_transaction = self.__formatteur_message.signer_message(
            message, routing_key, version=version)
        self._publish_public(message_signe, routing_key)
        return uuid_transaction, message_signe

    def relayer_direct(self, message: dict, queue_name: str, reply_to=None, correlation_id=None):
        self._publish_direct(message, queue_name, reply_to=reply_to, correlation_id=correlation_id)

    def _publish_direct(self, message, queue_name,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = ''  # Echange par defaut
        self.__publish(message, queue_name, echange, delivery_mode_v, encoding, reply_to, correlation_id,
                       publish_watch=True)

    def _publish_public(self, message, routing_key,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = self.__contexte.configuration.exchange_public
        self.__publish(message, routing_key, echange, delivery_mode_v, encoding, reply_to, correlation_id,
                       publish_watch=False)

    def _publish_prive(self, message, routing_key, delivery_mode_v=1,
                       encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = self.__contexte.configuration.exchange_prive
        self.__publish(message, routing_key, echange, delivery_mode_v, encoding, reply_to, correlation_id,
                       publish_watch=False)

    def _publish_protege(self, message, routing_key,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = self.__contexte.configuration.exchange_noeuds
        self.__publish(message, routing_key, echange, delivery_mode_v, encoding, reply_to, correlation_id)

    def _publish_secure(self, message, routing_key,
                delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None):
        echange = self.__contexte.configuration.exchange_middleware
        self.__publish(message, routing_key, echange, delivery_mode_v, encoding, reply_to, correlation_id)

    def __publish(self, message, routing_key, echange,
                  delivery_mode_v=1, encoding=DateFormatEncoder, reply_to=None, correlation_id=None,
                  publish_watch=True):

        properties = BasicProperties(delivery_mode=delivery_mode_v)
        if reply_to is not None:
            properties.reply_to = reply_to
        if correlation_id is not None:
            properties.correlation_id = correlation_id

        message_utf8 = TransmetteurMessageMilleGrilles.__json_helper.dict_vers_json(message, encoding)
        self.__logger.debug("publish message: %s" % message_utf8)
        with self.__channel_lock:
            # Utiliser pubdog pour la connexion publishing par defaut
            self.__channel.basic_publish(
                exchange=echange,
                routing_key=routing_key,
                body=message_utf8,
                properties=properties,
                mandatory=True
            )

            if publish_watch:
                self.publish_watch()

    def publish_watch(self):
        """
        Indique qu'on veut savoir si la connexion fonctionne (on s'attend a recevoir un confirm delivery moment donne)
        :return:
        """
        if not self.__published:
            if self.__thread_publishing_watchdog is None:
                if self.__thread_publishing_watchdog is None:
                    self.__thread_publishing_watchdog = Thread(name="PubDog_" + self.descriptif, target=self.__run_publishing_watchdog, daemon=True)
                    self.__thread_publishing_watchdog.start()
            else:
                # Reset timer du watchdog, aucun evenement en attente
                self.__publish_confirm_event.set()

            self.__published = True

    def __run_publishing_watchdog(self):
        """
        Main du watchdog de publication. Permet de detecter rapidement une connexion MQ qui ne repond plus.
        """

        self.__logger.warning("Demarrage watchdog publishing")

        while not self.__stop_event.is_set():

            if self.__published:

                # Attendre timeout ou confirmation de publication du message
                self.__publish_confirm_event.wait(1)

                if not self.__publish_confirm_event.is_set():
                    self.__logger.warning("Confirmation de publish non recue, erreur sur connexion")
                    if self.__callback_enter_error_state is not None:
                        self.__callback_enter_error_state()

                self.__published = False

            # Attendre prochain evenement de publish
            self.__publish_confirm_event.clear()
            self.__publish_confirm_event.wait(600)

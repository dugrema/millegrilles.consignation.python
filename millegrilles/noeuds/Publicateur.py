# Outil de publication de fichiers vers le web, associe a nginx

import time
import datetime
import pytz
import logging
import threading

from threading import Event, Thread
from pika.exceptions import ConnectionClosed, ChannelClosed

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration


class Publicateur(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self._stop_event = Event()
        self._stop_event.set()

        self.__channel = None
        self.__queue_reponse = None
        self._message_handler = None

        self.logger = logging.getLogger('Publicateur')

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)

        # Configuration MQ
        self._message_handler = TraitementPublication(self.contexte)
        self.contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel
        self.__channel.queue_declare(queue='', exclusive=True, callback=self.register_mq_hanlder)

    def register_mq_hanlder(self, queue):
        nom_queue = queue.method.queue
        exchange = Constantes.CONFIG_MQ_EXCHANGE_NOEUDS
        self.__queue_reponse = nom_queue
        self._logger.debug("Resultat creation queue: %s" % nom_queue)

        routing_keys = ['publicateur.#']

        for routing_key in routing_keys:
            self.__channel.queue_bind(queue=nom_queue, exchange=exchange, routing_key=routing_key, callback=None)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.deconnecter()

    def deconnecter(self):
        self._stop_event.set()
        super().deconnecter()

    def configurer_parser(self):
        super().configurer_parser()

        # self.parser.add_argument(
        #     '--debug', action="store_true", required=False,
        #     help="Active le debugging (logger)"
        # )

        self.parser.add_argument(
            '--webroot',
            type=str,
            required=True,
            help="Repertoire de base pour publier les fichiers"
        )

    def set_logging_level(self):
        super().set_logging_level()
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            # logging.getLogger('mgdomaines').setLevel(logging.DEBUG)
        elif self.args.info:
            self._logger.setLevel(logging.INFO)
            # logging.getLogger('mgdomaines').setLevel(logging.INFO)

    def executer(self):

        self._stop_event.clear()  # Pret a l'execution

        while not self._stop_event.is_set():
            self._stop_event.wait(30)


class TraitementPublication(BaseCallback):
    """
    Handler pour la Q du publicateur. Execute les commandes de publication.
    """

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._gestionnaire = gestionnaire
        self._generateur = gestionnaire.contexte.generateur_transactions

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        correlation_id = properties.correlation_id
        exchange = method.exchange

        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        enveloppe_certificat = self.contexte.verificateur_transaction.verifier(message_dict)

        if correlation_id is not None:
            # C'est une reponse
            pass
        elif routing_key is not None:
            pass
        else:
            raise ValueError("Message type inconnu")

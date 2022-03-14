import datetime
import json
import logging

from threading import Event
from typing import Optional

from millegrilles.dao.MessageDAO import BaseCallback


class ReplyQHandler(BaseCallback):
    """
    Genere une Q pour attendre des reponses blocking pour commandes et requetes.
    """

    def __init__(self, contexte):
        super().__init__(contexte)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.contexte.message_dao.register_channel_listener(self)
        self.channel = None
        self.event_recu = Event()
        self.__reply_q_name: Optional[str] = None

        self.__correlation_messages = dict()
        self.ready = Event()

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare('', durable=False, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.__reply_q_name = queue.method.queue
        self.__logger.info("Reply Queue: %s" % str(self.__reply_q_name))
        self.channel.basic_consume(self.__reply_q_name, self.callbackAvecAck, auto_ack=False)
        self.ready.set()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        correlation_id = properties.correlation_id
        self.__logger.debug("Recu reponse correlationId %s", correlation_id)
        try:
            reply_holder = self.__correlation_messages[correlation_id]
            reply_holder['reponse'] = body
            reply_holder['event'].set()  # Notify
        except KeyError:
            self.__logger.info("Recu message avec correlation inconnue : %s" % correlation_id)

    def requete(self, requete: dict, domaine: str, exchange=None, action: str = None, partition=None, blocking=True):

        uuid_transaction = self._contexte.generateur_transactions.transmettre_requete(
            requete, domaine,
            action=action,
            partition=partition,
            correlation_id=None,
            securite=exchange,
            reply_to=self.__reply_q_name,
            ajouter_certificats=True
        )

        if blocking:
            return self._attendre_reponse(uuid_transaction)
        else:
            return uuid_transaction

    def commande(self, commande: dict, domaine: str, channel=None, exchange=None, action: str = None, version=1, partition=None, blocking=True):
        uuid_transaction = self._contexte.generateur_transactions.transmettre_commande(
            commande, domaine,
            action=action,
            partition=partition,
            version=version,
            channel=channel,
            exchange=exchange,
            reply_to=self.__reply_q_name,
            ajouter_certificats=True
        )

        if blocking:
            return self._attendre_reponse(uuid_transaction)
        else:
            return uuid_transaction, None

    def _attendre_reponse(self, uuid_transaction: str):
        try:
            self.__logger.debug("Attendre reponse au message %s" % uuid_transaction)
            event_attente = Event()
            self.__correlation_messages[uuid_transaction] = {
                'event': event_attente,
                'creation': datetime.datetime.utcnow(),
            }

            event_attente.wait(30)  # Attendre 30 secondes pour la reponse

            if event_attente.is_set():
                # Une reponse a ete recue
                resultat = self.__correlation_messages[uuid_transaction]['reponse']

                message_dict = json.loads(resultat)
                validateur = self.contexte.validateur_message
                enveloppe = validateur.verifier(message_dict)
                if enveloppe is None:
                    # Reponse signature ou hachage invalide
                    return None, None

                return message_dict, enveloppe
            else:
                return None, None
        finally:
            # Cleanup
            del self.__correlation_messages[uuid_transaction]

    @property
    def reply_q_name(self):
        return self.__reply_q_name

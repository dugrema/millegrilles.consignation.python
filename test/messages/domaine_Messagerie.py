from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMessagerie
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from threading import Event

import json
import datetime
import uuid

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.queue_name = None

        self.channel = None
        self.event_recu = Event()

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare('', durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.queue_name, self.callbackAvecAck, auto_ack=False)
        self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        message = json.loads(str(body, 'utf-8'))
        print(json.dumps(message, indent=4))

    def poster_message(self):
        requete = {
            'to': ['@proprietaire/mg-dev5.maple.maceroc.com'],
            'cc': [],
            'bcc': [],
            'from': '@mathieu/mg-dev5.maple.maceroc.com',
            'reply_to': '@mathieu/mg-dev5.maple.maceroc.com',
            'subject': 'Un message de test',
            'content': 'Du contenu de message test.',
            'attachments': [],
        }
        domaine = ConstantesMessagerie.DOMAINE_NOM
        action = 'poster'
        enveloppe = self.generateur.transmettre_commande(
            requete,
            domaine=domaine, action=action, exchange=Constantes.SECURITE_PRIVE,
            correlation_id='abcd-1234', reply_to=self.queue_name,
            ajouter_certificats=True,
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def executer(self):
        self.poster_message()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()



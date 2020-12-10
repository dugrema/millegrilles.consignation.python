# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

from threading import Event, Thread


class DomaineTest(BaseCallback):

    def __init__(self, connecter=True):
        contexte = ContexteRessourcesMilleGrilles()
        contexte.initialiser(connecter=connecter)

        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.channel = None
        self.event_recu = Event()
        self.messages = list()

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)

        thread = Thread(name="executer", target=self.executer)
        thread.start()
        # self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        contenu = json.loads(body.decode('utf-8'))
        self.messages.append(contenu)
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(json.dumps(contenu, indent=4))
        print("Channel : " + str(ch))
        print("Method : " + str(method))
        print("Properties : " + str(properties))
        print("Channel virtual host : " + str(ch.connection.params.virtual_host))
        self.event_recu.set()

    def executer(self):
        raise NotImplementedError()

# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.Constantes import ConstantesPlume
from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.uuid_blogpost = '3c38abee-3d68-11ea-be1a-00155d011f09'

        self.channel = None
        self.event_recu = Event()

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)

    def maj_blogpost(self):
        transaction = {
            "titre": "title blogpost",
            "titre_fr": "Titre blogpost",
            "texte": "Text blogpost",
            "texte_fr": "Texte du blogpost",
            'uuid': self.uuid_blogpost,
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesPlume.TRANSACTION_MAJ_BLOGPOST,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Transaction: %s" % enveloppe_val)
        return enveloppe_val

    def publier_blogpost(self):
        transaction = {
            'uuid': self.uuid_blogpost
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesPlume.TRANSACTION_PUBLIER_BLOGPOST,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Transaction: %s" % enveloppe_val)
        return enveloppe_val

    def retirer_blogpost(self):
        transaction = {
            'uuid': self.uuid_blogpost
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesPlume.TRANSACTION_RETIRER_BLOGPOST,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Transaction: %s" % enveloppe_val)
        return enveloppe_val

    def supprimer_blogpost(self):
        transaction = {
            'uuid': self.uuid_blogpost
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesPlume.TRANSACTION_SUPPRIMER_BLOGPOST,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Transaction: %s" % enveloppe_val)
        return enveloppe_val

    def executer(self):
        # sample.maj_blogpost()
        # sample.publier_blogpost()
        # sample.retirer_blogpost()
        sample.supprimer_blogpost()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()


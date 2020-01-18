# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.Constantes import ConstantesGrosFichiers
from millegrilles.domaines.Principale import ConstantesPrincipale
from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.collection_uuid = "1383dca0-37dc-11ea-acfe-00155d011f09"
        self.collection_figee = "fcc64a32-396d-11ea-be1a-00155d011f09"

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

    def set_securite_collection_prive(self):
        transaction = {
            "uuid": self.collection_uuid,
            "niveau_securite_destination": "2.prive",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_CHANGER_SECURITE_COLLECTION,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Changement securite: %s" % enveloppe_val)
        return enveloppe_val

    def set_securite_collection_public(self):
        transaction = {
            "uuid": self.collection_uuid,
            "niveau_securite_destination": "1.public",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_CHANGER_SECURITE_COLLECTION,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Changement securite: %s" % enveloppe_val)
        return enveloppe_val

    def publier_collection(self):
        transaction = {
            "uuid": self.collection_figee,
            "url_web": "https://localhost"
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_PUBLIER_COLLECTION,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Publier collection figee: %s" % enveloppe_val)
        return enveloppe_val

    def executer(self):
        # sample.set_securite_collection_prive()
        # sample.set_securite_collection_public()
        sample.publier_collection()

        pass


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()


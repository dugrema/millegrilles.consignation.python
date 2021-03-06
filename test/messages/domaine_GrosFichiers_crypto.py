# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Principale import ConstantesPrincipale
from threading import Thread, Event

import json
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
        message = json.loads(str(body, 'utf-8'))
        print(json.dumps(message, indent=4))

    def transmettre_commande_decrypter_fichier(self):
        commande = {
            'fuuid': 'be7fbda0-17ba-11ea-8ac1-478d8dc0ec27',
            'cleSecreteDecryptee': 'MzJmZjAwNmZkOTE2YTFjODk5MjM4ZDE5YmUwNzhjMThjNzdjNTViZDQyZWJkYjAwMjdhYTZjY2JkZGU0NDM3Nw==',
            'iv': 'HdIAp2jtPFoddGqeCzw92A==',
        }
        enveloppe_val = self.generateur.transmettre_commande(
            commande, 'commande.grosfichiers.decrypterFichier')

        print("Envoi commande torrent: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_transaction_decrypterFichier(self):
        commande = {
            'fuuid': '9158c187-f560-11ea-a914-1b4edbfd1a69',
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            commande, 'millegrilles.domaines.GrosFichiers.decrypterFichier')

        print("Envoi transaction decryter fichier: %s" % enveloppe_val)
        return enveloppe_val

    def executer(self):
        # enveloppe = sample.transmettre_transaction_decrypterFichier()
        enveloppe = sample.transmettre_commande_decrypter_fichier()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()


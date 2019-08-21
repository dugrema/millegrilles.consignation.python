# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.MaitreDesCles import ConstantesMaitreDesCles

from threading import Event, Thread

class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(ContexteRessourcesMilleGrilles())
        self.contexte.initialiser(init_document=False)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.message_dao = self.contexte.message_dao
        self.channel = None
        self.event_recu = Event()
        self.thread_ioloop = Thread(target=self.run_ioloop)

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
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
        self.event_recu.set()

    def requete_cert_maitredescles(self):
        requete_cert_maitredescles = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def nouvelle_cle(self):

        nouvelle_cle = {
            "domaine": "millegrilles.domaines.GrosFichiers",
            "fuuid": "02d569a0-c388-11e9-b478-630aa73a3f1e",
            "fingerprint": "abcd",
            "cle": "bIteZjNBYmWP482k1OFzBn56OD+2R3QS8I3vxtUsUl30k9j7Zvolom2vYcVmtqxKcYfNTJDwxqT5T/F+D5ooFTUgDT1/md1BvCDeicqh5+daVAK2P5kKRWklQkAkldrUgUthW3CjVtwkDb0D1tKdwWGasF6IKWtI+MZv3Z2pB+o+Oz7etZhlaaWmL7ncfPQn/lFaf2JgskpV1zJDfbipilEtxqAA/U50hEAbuFajm+eJyfrNrTA+n5M6gnscDVyeRa7uozU3QRoMaB1/v8vo3lUHVqS/fxaeToc0oqcdJRObWP9uTGhvZ4cg8lDjQwci7P2AjFAaDsgpYolWb3SnPQ==",
            "iv": "gA8cRaiJE+8aN2c6/N1vTg==",
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            nouvelle_cle,
            'millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_GROSFICHIER,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def executer(self):
        # enveloppe = sample.requete_cert_maitredescles()
        enveloppe = sample.nouvelle_cle()

# --- MAIN ---
sample = MessagesSample()

# TEST
sample.thread_ioloop.start()

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

# Script de test pour transmettre message de transaction

import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Pki import ConstantesPki

from threading import Event, Thread

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()

class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.fichier_fuuid = "39c1e1b0-b6ee-11e9-b0cd-d30e8fab842j"

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
        print(json.dumps(json.loads(body.decode('utf-8')), indent=4))
        print("Channel : " + str(ch))
        print("Method : " + str(method))
        print("Properties : " + str(properties))
        print("Channel virtual host : " + str(ch.connection.params.virtual_host))

    def requete_dechiffrage_cle(self, hachage: list):
        requete_cert_maitredescles = {
            "liste_hachage_bytes": hachage,
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles',
            action="dechiffrage",
            correlation_id='abcd-1234',
            reply_to=self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def executer(self):
        # for i in range(0, 5000):

        self.requete_dechiffrage_cle([
            "zSEfXUAkCH41Z2FRVu5Faujutzjeo15XU7V9eH1zBwgBKP3NH6u4RsTBdTuzc8aPHkn8nsUZCeprmRYdGcUSMcBJvEmZP7",
            "zSEfXUBxGsjZHc7BYnfc4CsFq5KZTQWncxWdaEraWBbTrirtoEGVe7y93owEsxvgBqKBPVDZ5WkDivadW8cwWcFWaw1j4T",
            "zSEfXUA7wkH3mmKHKrAbnR4Xtbj86cNTsdvr93A6vBFjhXgJvaKEjqS5N1JwAdCFKV1UvbdXojJZhkhFMp2HyfbY7KgpVM",
        ])


# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(20)
sample.deconnecter()

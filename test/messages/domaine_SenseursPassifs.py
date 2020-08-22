# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import datetime
import time
import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.domaines.SenseursPassifs import SenseursPassifsConstantes

from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


SAMPLE_TRANSACTION_1 = {
    "_signature": "UlJjL37P/AiCylFfVdCB6O9pUZin8rGXj98MmMXT6zsxLtYb2iTfsEl2ZhvBVrPFc2FVcNKu42ddm5Rj0r1J+sJWmHQ+roJgxl3MLRTfU5Ze535gJtrLJkBJMV/Cj3x59mUgfITkgSYEA1s6KHhWfpNz8p97I/F5yb1xsRkkAGLD0jRFVYmyRs/ly1NQhVwFD93QSnyQFlCDxtSoZGbKWUjhRdGVPrUYvzzJKIjF5A+xnaQKmpxMyTHErtwaWWdGEwmpVVoYy0OqLmccFD++A3IP4bF80cQT28up4zIqYaHDMAZ4LeIqypVURl4QEAbQiX0Quxfo1zCCSBRbC9nRJw==",
    "avg": 1.31,
    "en-tete": {
        "certificat": "a9f1e440b4abb7b0d96016bdbce4350a757eb298",
        "domaine": "SenseursPassifs.lecture",
        "estampille": 1597967118,
        "hachage-contenu": "hj/wUh7pITZEgwAcDlurWPpWPBLld8eBEOQHbRNX+6M=",
        "idmg": "a7zqgVFc6LtqSerLA2asNBZspgkM35fbhn4DZcRH3H43",
        "uuid-transaction": "3427be78-e33f-11ea-95a1-5f9f064cecea",
        "version": 6
    },
    "lectures": [{
        "timestamp": 1597950486,
        "valeur": 31.4
    }, {
        "timestamp": 1597950491,
        "valeur": 5.3
    }, {
        "timestamp": 1597953581,
        "valeur": -0.4
    }, {
        "timestamp": 1597953586,
        "valeur": 38.9
    }, {
        "timestamp": 1597953591,
        "valeur": 42.2
    }, {
        "timestamp": 1597953596,
        "valeur": -49.3
    }
    ],
    "max": 49.9,
    "min": -49.6,
    "noeud_id": "001a12f5-e89d-4ff8-b6ac-f2ee269b9516",
    "timestamp": 1597950000,
    "timestamp_max": 1597953596,
    "timestamp_min": 1597950491,
    "type": "temperature",
    "uuid_senseur": "7a2764fa-c457-4f25-af0d-0fc915439b21"
}


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
        print(json.dumps(json.loads(body.decode('utf-8')), indent=4))
        print("Channel : " + str(ch))
        print("Method : " + str(method))
        print("Properties : " + str(properties))
        print("Channel virtual host : " + str(ch.connection.params.virtual_host))

    def transmettre_transaction_lecture(self):
        transaction = {
            "avg": 1.31,
            "lectures": [{
                "timestamp": 1597950486,
                "valeur": 31.4
            }, {
                "timestamp": 1597950491,
                "valeur": 5.3
            }, {
                "timestamp": 1597953581,
                "valeur": -0.4
            }, {
                "timestamp": 1597953586,
                "valeur": 38.9
            }, {
                "timestamp": 1597953591,
                "valeur": 42.2
            }, {
                "timestamp": 1597953596,
                "valeur": -49.3
            }
            ],
            "max": 49.9,
            "min": -49.6,
            "noeud_id": "001a12f5-e89d-4ff8-b6ac-f2ee269b9516",
            "senseur": "dummy/temperature",
            "timestamp": 1597950000,
            "timestamp_max": 1597953596,
            "timestamp_min": 1597950491,
            "type": "temperature",
            "uuid_senseur": "7a2764fa-c457-4f25-af0d-0fc915439b21"
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'SenseursPassifs.lecture',
            reply_to=self.queue_name, correlation_id='efgh')

        print("Envoi metadata: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_maj_noeud(self):
        transaction = {
            "noeud_id": "001a12f5-e89d-4ff8-b6ac-f2ee269b9516",
            "securite": "2.prive",
            "blynk_host": "blynk",
            "blynk_port": 9443,
            "blynk_auth": "p2ADaQx9Q6lH88jN4NK8ILdprD104xMf"
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, SenseursPassifsConstantes.TRANSACTION_MAJ_NOEUD,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def transmettre_maj_senseur(self):
        transaction = {
            "uuid_senseur": "7a2764fa-c457-4f25-af0d-0fc915439b21",
            "securite": "2.prive",
            "senseurs": {"dummy/humidite": {"blynk_vpin": None}},
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, SenseursPassifsConstantes.TRANSACTION_MAJ_SENSEUR,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def executer(self):
        # sample.transmettre_transaction_lecture()
        # sample.transmettre_maj_noeud()
        sample.transmettre_maj_senseur()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()
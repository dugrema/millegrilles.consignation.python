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

sample_app_1 = {
    "nom": "test_container",
    "registries": [
        ""
    ],
    "images": {
        "nginx": {
            "image": "nginx",
            "version": "latest"
        }
    },
    "dependances": [
        {
            "image": "nginx",
            "container_mode": True,
            "config": {
                "name": "nginx_dummy",
                "environment": [
                    "MG_MQ_URL=amqps://mq:5673",
                    "MG_MQ_CERTFILE=/run/secrets/cert.pem",
                    "MG_MQ_KEYFILE=/run/secrets/key.pem",
                    "MG_MQ_CAFILE=/run/secrets/millegrille.cert.pem",
                ],
                "mounts": [
                    {
                        'target': '/home/mathieu',
                        'source': '/home/mathieu',
                        'type': 'bind'
                    }
                ],
                "network": "millegrille_net",
                "devices": [
                    "/dev/sda:/dev/sda:rwm"
                ]
            }
        }
    ]
}


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

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

    def installer_application_prive_dummy(self):
        commande = {
            'nom_application': 'con_dummy',
            'configuration': sample_app_1,
        }
        domaineAction = 'commande.servicemonitor.79b2f503-5f93-4019-b9e0-fc14686fc695.' + Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PRIVE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def executer(self):
        # self.renouveller_certs_docker()
        # self.requete_cert_backup()
        self.installer_application_prive_dummy()


# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

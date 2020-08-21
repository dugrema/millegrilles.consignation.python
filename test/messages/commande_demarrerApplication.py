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
                    "MG_IDMG=${IDMG}",
                    "MG_MQ_HOST=${MQ_HOST}",
                    "MG_MQ_PORT=${MQ_PORT}",
                    "MG_MQ_SSL=on",
                    "MG_MQ_AUTH_CERT=on",
                    "MG_MQ_CERTFILE=/run/secrets/cert.pem",
                    "MG_MQ_KEYFILE=/run/secrets/key.pem",
                    "MG_MQ_CAFILE=/run/secrets/millegrille.cert.pem"
                ],
                "mounts": [
                    {
                        'target': '/home/mathieu',
                        'source': '/home/mathieu',
                        'type': 'bind'
                    }
                ],
                "network": "millegrille_net",
                # "devices": [
                #    "/dev/sda:/dev/sda:rwm"
                # ],
                "privileged": True,
                # "restart_policy": {"Name": "always", "MaximumRetryCount": 10}
                "restart_policy": {"Name": "on-failure", "MaximumRetryCount": 3}
            }
        }
    ]
}

blynk_app = {
    "nom": "blynk",
    "registries": [
        "docker.maceroc.com",
        "dugremat"
    ],
    "images": {
        "blynk": {
            "image": "mg_blynk",
            "version": "0.41.10_2"
        },
        "blynk_client": {
            "registries": [""],
            "image": "alpine",
            "version": "latest"
        }
    },
    "dependances": [
        {
            "image": "blynk",
            "config": {
                "name": "blynk",
                "constraints": [
                    "node.labels.millegrilles.app.blynk == true"
                ],
                "env": [
                    "SERVER_SSL_KEY=/run/secrets/webkey.pem",
                    "SERVER_SSL_CERT=/run/secrets/webcert.pem"
                ],
                "configs": [
                    {
                        "name": "pki.blynk.cert",
                        "filename": "/run/secrets/webcert.pem"
                    }
                ],
                "secrets": [
                    {
                        "name": "pki.blynk.key",
                        "filename": "webkey.pem"
                    }
                ],
                "mounts": [
                    "blynk_data:/blynk/data:rw"
                ],
                "endpoint_spec": {
                    "mode": "vip",
                    "ports": [{
                        "published_port": 9443,
                        "target_port": 9443,
                        "protocol": "tcp",
                        "publish_mode": "host"
                    }]
                },
                "networks": [{
                    "target": "millegrille_net"
                }],
                "labels": {
                    "millegrille": "${IDMG}"
                },
                "resources": {
                    "cpu_limit": 1000000000,
                    "mem_limit": 100000000
                },
                "mode": {
                    "mode": "replicated",
                    "replicas": 1
                }
            }
        },
        {
            "image": "blynk_client",
            "command": "/bin/sleep 10000",
            "etape_seulement": True,
            "backup": {
                "base_path": "/tmp/backup"
            },
            "config": {
                "name": "blynk_client",
                "constraints": [
                    "node.labels.millegrilles.app.blynk == true"
                ],
                "mounts": [
                    "blynk_data:/tmp/backup/data:rw"
                ],
                "labels": {
                    "millegrille": "${IDMG}"
                },
                "resources": {
                    "cpu_limit": 1000000000,
                    "mem_limit": 50000000
                },
                "mode": {
                    "mode": "replicated",
                    "replicas": 1
                }
            }
        }
    ]
}

senseurspassifs_app = {
    "nom": "senseurspassifs_rpi",
    "registries": [
        "docker.maceroc.com",
        "dugrema"
    ],
    "images": {
        "millegrilles_senseurspassifs_rpi": {
            "image": "millegrilles_senseurspassifs_rpi",
            "version": "armv7l_1.31.0"
        }
    },
    "dependances": [
        {
            "image": "millegrilles_senseurspassifs_rpi",
            "container_mode": True,
            "injecter_clecert": "/run/secrets",
            "config": {
                "command": ["python3", "-m", "mgraspberry.raspberrypi.Demarreur", "--rf24master", "--dummy", "nofork"],
                # "command": ["sleep", "10000"],
                "name": "senseurspassifs_rpi",
                "environment": [
                    "MG_IDMG=${IDMG}",
                    "MG_MQ_HOST=${MQ_HOST}",
                    "MG_MQ_PORT=${MQ_PORT}",
                    "MG_MQ_SSL=on",
                    "MG_MQ_AUTH_CERT=on",
                    "MG_MQ_CERTFILE=/run/secrets/cert.pem",
                    "MG_MQ_KEYFILE=/run/secrets/key.pem",
                    "MG_MQ_CA_CERTS=/run/secrets/millegrille.cert.pem"
                ],
                "mounts": [
                    {
                        'target': '/opt/dist/config',
                        'source': 'senseurspassifs-config',
                        'type': 'volume'
                    }
                ],
                "network": "millegrille_net",
                "privileged": True
            }
        }
    ]
}

uuid_service_monitor = 'e94d95ba-d193-46bf-ad0d-6abc8e21fcd4'

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

    def installer_application_protege_dummy(self):
        commande = {
            'nom_application': 'con_dummy',
            'configuration': sample_app_1,
        }
        domaineAction = 'commande.servicemonitor.3fd2e404-7b4f-4d1c-b2c4-544c5833d37d.' + Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def supprimer_application_protege_dummy(self):
        commande = {
            'nom_application': 'con_dummy',
            'configuration': sample_app_1,
        }
        domaineAction = 'commande.servicemonitor.3fd2e404-7b4f-4d1c-b2c4-544c5833d37d.' + Constantes.ConstantesServiceMonitor.COMMANDE_SUPPRIMER_APPLICATION

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def installer_application_senseurspassifs(self):
        commande = {
            'nom_application': 'senseurspassifs',
            'configuration': senseurspassifs_app,
        }
        domaineAction = 'commande.servicemonitor.47330762-98a6-4bb2-9172-115cfea92a8d.' + Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PRIVE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def supprimer_application_senseurspassifs(self):
        commande = {
            'nom_application': 'senseurspassifs',
            'configuration': senseurspassifs_app,
        }
        domaineAction = 'commande.servicemonitor.47330762-98a6-4bb2-9172-115cfea92a8d.' + Constantes.ConstantesServiceMonitor.COMMANDE_SUPPRIMER_APPLICATION

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PRIVE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def installer_application_blynk(self):
        commande = {
            'nom_application': 'blynk',
            'configuration': blynk_app,
        }
        domaineAction = 'commande.servicemonitor.%s.%s' % (uuid_service_monitor, Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION)

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def executer(self):
        # self.renouveller_certs_docker()
        # self.requete_cert_backup()
        # self.installer_application_protege_dummy()
        # self.supprimer_application_protege_dummy()
        # self.installer_application_senseurspassifs()
        # self.supprimer_application_senseurspassifs()
        self.installer_application_blynk()


# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

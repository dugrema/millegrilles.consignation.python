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

redmine = {
    "nom": "redmine.mariadb",
    "registries": [
        "docker.maceroc.com",
        "dugremat"
    ],
    "images": {
        "mariadb": {
            "registries": [
                ""
            ],
            "image": "mariadb",
            "version": "10.5"
        },
        "redmine": {
            "image": "mg_redmine",
            "version": "4.1_0"
        }
    },
    "dependances": [
        {
            "docker_config_file": "docker.mariadb.sharedapp.json",
            "shared": True
        },
        {
            "image": "mariadb",
            "etape_seulement": True,
            "installation": {
                "commande": "/usr/local/scripts/script.redmine.mariadb.installation.sh",
                "fichiers": [
                    "script.redmine.mariadb.installation.sh"
                ],
                "exit_codes_ok": [1]
            },
            "backup": {
                "commande_backup": "/usr/local/scripts/script.redmine.mariadb.backup.sh",
                "commande_restore": "/usr/local/scripts/script.redmine.mariadb.restore.sh",
                "fichiers": [
                    "script.redmine.mariadb.backup.sh",
                    "script.redmine.mariadb.restore.sh"
                ],
                "base_path": "/tmp/backup"
            },
            "generer": {
                "motsdepasse": [
                    {"name": "passwd.redmine"},
                    {"name": "passwd.mariadb"}
                ]
            },
            "config": {
                "name": "mariadb_redmine_client",
                "args": ["sleep", "10000"],
                "env": [
                    "PATH_SCRIPTS=/usr/local/scripts",
                    "REDMINE_DB_PASSWORD_FILE=/run/secrets/redmine-passwd",
                    "MARIADB_PASSWORD_FILE=/run/secrets/mariadb-passwd"
                ],
                "constraints": [
                    "node.labels.millegrilles.app.redmine == true"
                ],
                "mounts": [
                    "redmine_files:/tmp/backup/files:rw",
                    "redmine_scripts:/usr/local/scripts:rw"
                ],
                "secrets": [
                    {
                        "name": "passwd.redmine",
                        "filename": "redmine-passwd"
                    }, {
                        "name": "passwd.mariadb",
                        "filename": "mariadb-passwd"
                    }
                ],
                "networks": [{
                    "target": "millegrille_net"
                }],
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
        },
        {
            "image": "redmine",
            "config": {
                "name": "redmine",
                "env": [
                    "REDMINE_DB_PASSWORD_FILE=/run/secrets/redmine-passwd",
                    "REDMINE_DB_MYSQL=mariadb",
                    "REDMINE_DB_USERNAME=redmine",
                    "REDMINE_DB_DATABASE=redmine"
                ],
                "mounts": [
                    "redmine_files:/usr/src/redmine/files:rw"
                ],
                "constraints": [
                    "node.labels.millegrilles.app.redmine == true"
                ],
                "secrets": [
                    {
                        "name": "passwd.redmine",
                        "filename": "redmine-passwd"
                    }
                ],
                "networks": [
                    {
                        "target": "millegrille_net",
                        "aliases": ["redmine"]
                    }
                ],
                "labels": {
                    "millegrille": "${IDMG}"
                },
                "resources": {
                    "cpu_limit": 1000000000,
                    "mem_limit": 209715200
                },
                "mode": {
                    "mode": "replicated",
                    "replicas": 1
                }
            }
        }
    ],
    "nginx": {
        "server_file": "nginx.redmine.mariadb.conf",
        "subdomain": "redmine",
        "params": {
            "PROXY_PASS_BACKEND": "http://redmine:3000"
        }
    }
}

mongoexpress = {
    "nom": "mongoexpress",
    "version": "1.31.0",
    "registries": [
        "docker.maceroc.com",
        "dugremat"
    ],
    "images": {
        "mongoexpress": {
            "image": "mg_mongo_express",
            "version": "0.49_5"
        }
    },
    "dependances": [
        {
            "image": "mongoexpress",
            "config": {
                "name": "mongoexpress",
                "certificat_compte": "pki.mongoxp.cert",
                "env": [
                    "ME_CONFIG_BASICAUTH_USERNAME=mongo",
                    "ME_CONFIG_MONGODB_ADMINUSERNAME=${MONGO_INITDB_ROOT_USERNAME}",
                    "MONGODB_ADMINPASSWORD_FILE=/run/secrets/mongo.password.txt",
                    "ME_CONFIG_BASICAUTH_PASSWORD_FILE=/run/secrets/web.password.txt",
                    "VCAP_APP_PORT=443",
                    "ME_CONFIG_SITE_SSL_ENABLED='true'",
                    "ME_CONFIG_SITE_SSL_CRT_PATH=/run/secrets/web.cert.pem",
                    "ME_CONFIG_SITE_SSL_KEY_PATH=/run/secrets/web.key.pem",
                    "ME_CONFIG_MONGODB_SERVER=mongo",
                    "ME_CONFIG_MONGODB_SSL=true",
                    "ME_CONFIG_MONGODB_KEY=/run/secrets/key.pem",
                    "ME_CONFIG_MONGODB_CERT=/run/secrets/cert.pem",
                    "ME_CONFIG_MONGODB_CACERT=/run/secrets/millegrille.cert.pem",
                    "ME_CONFIG_MONGODB_SSLVALIDATE='true'"
                ],
                "constraints": [
                    "node.labels.millegrilles.database == true"
                ],
                "configs": [
                    {
                        "name": "pki.mongoxp.cert",
                        "filename": "/run/secrets/cert.pem"
                    },
                    {
                        "name": "pki.mongoxp.cert",
                        "filename": "/run/secrets/web.cert.pem"
                    },
                    {
                        "name": "pki.millegrille.cert",
                        "filename": "/run/secrets/millegrille.cert.pem"
                    }
                ],
                "secrets": [
                    {
                        "match_config": True,
                        "name": "pki.mongoxp.key",
                        "filename": "key.pem"
                    },
                    {
                        "match_config": True,
                        "name": "pki.mongoxp.key",
                        "filename": "web.key.pem"
                    },
                    {
                        "name": "passwd.mongo",
                        "filename": "mongo.password.txt"
                    },
                    {
                        "name": "passwd.mongoxpweb",
                        "filename": "web.password.txt"
                    }
                ],
                "container_labels": {
                    "ipv6.mapper.network": "mg_ipv6"
                },
                "endpoint_spec": {
                    "mode": "vip",
                    "ports": [
                        {
                            "published_port": 10443,
                            "target_port": 443,
                            "protocol": "tcp",
                            "publish_mode": "host"
                        }
                    ]
                },
                "networks": [
                    {
                        "target": "millegrille_net",
                        "aliases": [
                            "mongoexpress"
                        ]
                    }
                ],
                "labels": {
                    "millegrille": "${IDMG}"
                },
                "resources": {
                    "cpu_limit": 500000000,
                    "mem_limit": 73741824
                },
                "restart_policy": {
                    "condition": "on-failure",
                    "delay": 60000000000,
                    "max_attempts": 5
                },
                "mode": {
                    "mode": "replicated",
                    "replicas": 1
                }
            }
        }
    ]
}

uuid_service_monitor = '6f1f11c8-d70d-45ef-b13c-2965b73c71b2'


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
        domaineAction = 'commande.servicemonitor.%s.%s' % (
            uuid_service_monitor, Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION)

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def supprimer_application_blynk(self):
        commande = {
            'nom_application': 'blynk',
            'configuration': blynk_app,
        }
        domaineAction = 'commande.servicemonitor.%s.%s' % (
            uuid_service_monitor, Constantes.ConstantesServiceMonitor.COMMANDE_SUPPRIMER_APPLICATION)

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def installer_application_redmine(self):
        commande = {
            'nom_application': 'redmine',
            'configuration': redmine,
        }
        domaineAction = 'commande.servicemonitor.%s.%s' % (
            uuid_service_monitor, Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION)

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def supprimer_application_redmine(self):
        commande = {
            'nom_application': 'redmine',
            'configuration': redmine,
        }
        domaineAction = 'commande.servicemonitor.%s.%s' % (
            uuid_service_monitor, Constantes.ConstantesServiceMonitor.COMMANDE_SUPPRIMER_APPLICATION)

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def installer_application_mongoexpress(self):
        commande = {
            'nom_application': 'mongoexpress',
            'configuration': mongoexpress,
        }
        domaineAction = 'commande.servicemonitor.%s.%s' % (
            uuid_service_monitor, Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION)

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def supprimer_application_mongoexpress(self):
        commande = {
            'nom_application': 'mongoexpress',
            'configuration': mongoexpress,
        }
        domaineAction = 'commande.servicemonitor.%s.%s' % (
            uuid_service_monitor, Constantes.ConstantesServiceMonitor.COMMANDE_SUPPRIMER_APPLICATION)

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
        # self.installer_application_blynk()
        # self.supprimer_application_blynk()
        # self.installer_application_redmine()
        # self.supprimer_application_redmine()
        self.installer_application_mongoexpress()
        # self.supprimer_application_mongoexpress()


# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

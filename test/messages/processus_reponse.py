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
contexte.initialiser(init_document=False)


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

    def transmettre_reponse(self):
        reponse = {
            'resultats': [
                [
                    {'label': 1234}
                ]
            ]
        }
        enveloppe_val = self.generateur.transmettre_reponse(
            reponse, 'millegrilles.domaines.GrosFichiers.processus', '5deaa316fd7b6b69f45b3b24')

        print("Envoi resultat parametres: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_reponse_relle(self):
        reponse = {
            "_signature": "fbCZmeVWqDJ8ZwnanHFBHs3DT5JYBlMUtzajDU34JtMxDpDXK702Wo7TEx5M9TCxZaN+0mFUTEKYa8l8EUFz9A7+rY3TeR0SV4LkHSO5DXj1HBta34Lsg5KVU86S7hLZI0vrPjFCMAIALdmcsnuwC9K6OBhxhf37HfDGVrfOmwNJdY4R8HV6U7YNPnKBV+sw0bkxZC8jU2Sw+dKhkUJunYnd81mLX29lmQ6nT2FQoRX5olF1h+zFo6C+2m0rroh2uUzgr4Kb2K6kjNdTj2/DPR4TgSw1jJtPdATjBiqp1Lbcy9dHCrJ7+WBsPwFwPxpsuOaGBv+YSvXVF2gt0kuDQg==",
            "en-tete": {
                "certificat": "8f3e528bb8c7d489b6b296b07b16db2bf76fa729",
                "estampille": 1575662185,
                "hachage-contenu": "4/RiVlGWDPBtDU3vkSacQXKmeZZL38x2mPCltxvD6a0=",
                "source-systeme": "mathieu/mg-dev3@mg-dev3",
                "uuid-transaction": "7bcc7946-1862-11ea-9318-00155d011f09",
                "version": 4
            },
            "resultats": [
                [
                    {
                        "_id": "5dd4306e4da41cd44b2463aa",
                        "_mg-creation": 1574187118.502,
                        "_mg-derniere-modification": 1574187118.503,
                        "_mg-libelle": "publique.configuration",
                        "actif": False,
                        "activite": [],
                        "ipv4_externe": None,
                        "mappings_ipv4": {},
                        "mappings_ipv4_demandes": {},
                        "noeud_docker_hostname": None,
                        "port_http": 80,
                        "port_https": 443,
                        "port_mq": 5673,
                        "status_info": None,
                        "upnp_supporte": False,
                        "url_mq": None,
                        "url_web": None
                    }
                ]
            ]
        }

        enveloppe_val = self.generateur.transmettre_reponse(
            reponse, 'millegrilles.domaines.GrosFichiers.processus', '5deaa406fd7b6b69f45b3b28')

        print("Envoi resultat parametres: %s" % enveloppe_val)
        return enveloppe_val

    def test_rediriger_requete(self):
        requete = {
            "requetes": [
                {
                    "filtre": {
                        '_mg-libelle': 'publique.configuration'
                    }
                }
            ]
        }
        self.generateur.transmettre_requete(requete, 'millegrilles.domaines.Parametres', '5deaa316fd7b6b69f45b3b24', self.queue_name)

    def executer(self):
        # enveloppe = sample.transmettre_reponse()
        enveloppe = sample.transmettre_reponse_relle()
        # enveloppe = sample.test_rediriger_requete()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()


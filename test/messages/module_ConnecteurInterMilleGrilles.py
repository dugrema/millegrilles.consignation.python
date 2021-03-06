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

    def transmettre_commande_ouverture(self, idmg):
        commande = {
            'idmg': idmg
        }

        domaine = 'commande.inter.connecter'
        enveloppe_val = self.generateur.transmettre_commande(commande, domaine, exchange=self.configuration.exchange_prive)

        print("Envoi maj fiche privee: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_requete_directe(self, idmg):
        requete = {
            'texte': 'On va se promener plus loin'
        }

        domaine = 'donne.moi.des.fichiers'
        enveloppe_val = self.generateur.transmettre_requete(requete, domaine, idmg_destination=idmg, correlation_id='moimoi')

        print("Envoi maj fiche privee: %s" % enveloppe_val)
        return enveloppe_val

    def demander_csr(self):
        domaine = 'inter.genererCsr'
        self.generateur.transmettre_requete({}, domaine, 'abcd', self.queue_name)

    def executer(self):
        idmg = 'distant'
        # enveloppe = sample.transmettre_commande_ouverture(idmg)
        # enveloppe = sample.transmettre_requete_directe(idmg)
        self.demander_csr()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()


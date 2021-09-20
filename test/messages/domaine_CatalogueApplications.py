# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import datetime
import time
import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.domaines.CatalogueApplications import ConstantesCatalogueApplications

from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


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

    def requete_liste_domaines(self):
        requete = {}
        domaine_action = ConstantesCatalogueApplications.REQUETE_LISTE_DOMAINES
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_liste_applications(self):
        requete = {}
        domaine_action = ConstantesCatalogueApplications.DOMAINE_NOM  # ConstantesCatalogueApplications.REQUETE_LISTE_APPLICATIONS
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh',
            action=ConstantesCatalogueApplications.REQUETE_LISTE_APPLICATIONS
        )
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_domaine(self):
        requete = {'nom': 'SenseursPassifs'}
        domaine_action = ConstantesCatalogueApplications.REQUETE_INFO_DOMAINE
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_application(self):
        requete = {'nom': 'blynk'}
        domaine_action = ConstantesCatalogueApplications.REQUETE_INFO_APPLICATION
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def executer(self):
        # sample.requete_liste_domaines()
        # sample.requete_domaine()
        # sample.requete_liste_applications()
        sample.requete_application()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

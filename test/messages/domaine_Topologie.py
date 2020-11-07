# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import datetime
import time
import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.domaines.Topologie import ConstantesTopologie

from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()

NOEUD_ID = '43eee47d-fc23-4cf5-b359-70069cf06600'


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
        domaine_action = ConstantesTopologie.REQUETE_LISTE_DOMAINES
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_liste_noeuds(self):
        requete = {}
        domaine_action = ConstantesTopologie.REQUETE_LISTE_NOEUDS
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_liste_applications(self):
        requete = {'securite': '3.protege'}
        domaine_action = ConstantesTopologie.REQUETE_LISTE_APPLICATIONS_DEPLOYEES
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_liste_noeud_detail(self):
        requete = {
            'noeud_id': NOEUD_ID,
            'all_info': True,
        }
        domaine_action = ConstantesTopologie.REQUETE_LISTE_NOEUDS
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_info_domaine(self):
        requete = {'domaine': 'CatalogueApplications'}
        domaine_action = ConstantesTopologie.REQUETE_INFO_DOMAINE
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_info_noeud(self):
        requete = {'noeud_id': '5ee16193-49a3-443f-ae4e-894a65de647d'}
        domaine_action = ConstantesTopologie.REQUETE_INFO_NOEUD
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def transaction_ajouter_domaine(self):
        requete = {
            'noeud_id': '5ee16193-49a3-443f-ae4e-894a65de647d',
            "nom": "SenseursPassifs",
            "module": "millegrilles.domaines.SenseursPassifs",
            "classe": "GestionnaireSenseursPassifs"
        }
        domaine_action = ConstantesTopologie.TRANSACTION_AJOUTER_DOMAINE_DYNAMIQUE
        enveloppe_val = self.generateur.soumettre_transaction(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def transaction_supprimer_domaine(self):
        requete = {
            'noeud_id': '5ee16193-49a3-443f-ae4e-894a65de647d',
            "nom": "SenseursPassifs",
        }
        domaine_action = ConstantesTopologie.TRANSACTION_SUPPRIMER_DOMAINE_DYNAMIQUE
        enveloppe_val = self.generateur.soumettre_transaction(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def executer(self):
        # sample.requete_liste_domaines()
        sample.requete_liste_noeuds()
        # sample.requete_liste_applications()
        # sample.requete_liste_noeud_detail()
        # sample.requete_info_domaine()
        # sample.requete_info_noeud()
        # sample.transaction_ajouter_domaine()
        # sample.transaction_supprimer_domaine()

# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

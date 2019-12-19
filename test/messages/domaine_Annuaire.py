# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from threading import Event

import json


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


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

    def transmettre_maj_fiche_privee(self):
        fiche = {
            'usager': {
                'nom': 'Dugre',
                'prenom': 'Mathieu',
                'courriel': 'mathieu.dugre@mdugre.info'
            },
            'descriptif': 'Moi',
        }

        domaine = 'millegrilles.domaines.Annuaire.maj.fichePrivee'
        enveloppe_val = self.generateur.soumettre_transaction(
            fiche, domaine, reply_to=self.queue_name, correlation_id='abcd'
        )

        print("Envoi maj fiche privee: %s" % enveloppe_val)
        return enveloppe_val

    def requete_fiche_privee(self):
        self.generateur.transmettre_requete({}, 'millegrilles.domaines.Annuaire.fichePrivee', reply_to=self.queue_name, correlation_id='abcd')

    def executer(self):
        enveloppe = sample.transmettre_maj_fiche_privee()
        # sample.requete_fiche_privee()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()


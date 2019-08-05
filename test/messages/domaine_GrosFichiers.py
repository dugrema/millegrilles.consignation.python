# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Principale import ConstantesPrincipale


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(ContexteRessourcesMilleGrilles())
        self.contexte.initialiser(init_document=False)
        self.generateur = GenerateurTransaction(self.contexte)
        self.message_dao = self.contexte.message_dao

        # Enregistrer la reply-to queue
        self.channel = self.message_dao.channel
        queue = self.channel .queue_declare(durable=True, exclusive=True)
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)

    def transaction_nouvelle_version_metadata(self):
        transaction = {
            "fuuid": "39c1e1b0-b6ee-11e9-b0cd-d30e8faa8413",
            "securite": "prive",
            "chemin_repertoires": "/",
            "nom": "ExplorationGrosFichiers2.txt",
            "taille": 5478,
            "sha256": "739291ef2f7f3e0f945712112df9a62aeb2642d3828551f9fa3c95449a415e31",
            "mimetype": "test/plain",
            "reception": {
                "methode": "coupdoeil",
                "noeud": "public1.maple.mdugre.info"
            },
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.nouvelleVersion.metadata',
            reply_to=self.queue_name, correlation_id='efgh')

        print("Envoi metadata: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_nouvelle_version_transfertcomplete(self):
        transaction = {
            "fuuid": "39c1e1b0-b6ee-11e9-b0cd-d30e8faa8413",
            "sha256": "739291ef2f7f3e0f945712112df9a62aeb2642d3828551f9fa3c95449a415e30",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.nouvelleVersion.transfertComplete',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Envoi transfert complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_creer_repertoire(self):
        transaction = {
            "parent_id": "b805e784-b7ba-11e9-b4bb-00155d011f00",
            "repertoire": "sous_test",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.creerRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Envoi transfert complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_renommer_repertoire(self):
        transaction = {
            "repertoire_uuid": "8e2cb4f4-b7bc-11e9-a426-00155d011f00",
            "repertoire": "sous_test_change_2",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.renommerRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_renommer_repertoire(self):
        transaction = {
            "repertoire_uuid": "0b0b36ce-b7c4-11e9-a940-00155d011f00",
            "repertoire": "sous_test_change_2",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.renommerRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

# --- MAIN ---
sample = MessagesSample()

# TEST
# enveloppe = sample.requete_profil_usager()
# enveloppe1 = sample.transaction_nouvelle_version_metadata()
# enveloppe2 = sample.transaction_nouvelle_version_transfertcomplete()
# enveloppe3 = sample.transaction_creer_repertoire()
enveloppe4 = sample.transaction_renommer_repertoire()

sample.channel.start_consuming()

# FIN TEST
sample.deconnecter()

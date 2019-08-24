# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Principale import ConstantesPrincipale
from threading import Thread, Event


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(ContexteRessourcesMilleGrilles())
        self.contexte.initialiser(init_document=False)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.message_dao = self.contexte.message_dao

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
        print(body)

    def transaction_nouvelle_version_metadata(self):
        transaction = {
            "fuuid": "39c1e1b0-b6ee-11e9-b0cd-d30e8faa8418",
            "securite": "2.prive",
            "repertoire_uuid": '16e474e6-c116-11e9-a058-00155d011f00',
            "nom": "ExplorationGrosFichiers5.txt",
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
            "fuuid": "39c1e1b0-b6ee-11e9-b0cd-d30e8faa8418",
            "sha256": "739291ef2f7f3e0f945712112df9a62aeb2642d3828551f9fa3c95449a415e30",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.nouvelleVersion.transfertComplete',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Envoi transfert complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_creer_repertoire(self):
        transaction = {
            "parent_id": "dcf4359c-b7cd-11e9-9cfa-00155d011f00",
            "nom": "sous-test6-test1",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.creerRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Envoi transfert complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_renommer_repertoire(self):
        transaction = {
            "repertoire_uuid": "8e2cb4f4-b7bc-11e9-a426-00155d011f00",
            "nom": "sous_test_change_2",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.renommerRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_deplacer_repertoire(self):
        transaction = {
            "repertoire_uuid": "92ddd276-b7c6-11e9-81e1-00155d011f00",
            "parent_id": 'b805e784-b7ba-11e9-b4bb-00155d011f00',
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.deplacerRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_renommer_fichier(self):
        transaction = {
            "uuid": "ec2626aa-b7ce-11e9-a706-00155d011f00",
            "nom": 'Bashir Bouzouka 3!',
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.renommerFichier',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_deplacer_fichier(self):
        transaction = {
            "uuid": "ec2626aa-b7ce-11e9-a706-00155d011f00",
            "repertoire_uuid": 'c6da1c6e-b7cc-11e9-8c97-00155d011f00',
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.deplacerFichier',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_supprimer_fichier(self):
        transaction = {
            "uuid": "ec2626aa-b7ce-11e9-a706-00155d011f00",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.supprimerFichier',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_supprimer_repertoire(self):
        transaction = {
            "repertoire_uuid": "392405b4-b7cd-11e9-831d-00155d011f00",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.supprimerRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_commenter_repertoire(self):
        transaction = {
            "repertoire_uuid": "408f2b1c-b7cd-11e9-831d-00155d011f00",
            "commentaires": "J'ai un commentaire. Ye! Pis on en rajoute."
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.commenterRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_changersecurite_repertoire(self):
        transaction = {
            "repertoire_uuid": "16e474e6-c116-11e9-a058-00155d011f00",
            "securite": "2.prive"
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.changerSecuriteRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_commenter_fichier(self):
        transaction = {
            "uuid": "1127ef4a-b7d1-11e9-8ec6-00155d011f00",
            "commentaires": "J'ai un commentaire. Ye! Pis on en rajoute."
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.commenterFichier',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def executer(self):
        # enveloppe = sample.requete_profil_usager()
        # enveloppe1 = sample.transaction_nouvelle_version_metadata()
        # enveloppe2 = sample.transaction_nouvelle_version_transfertcomplete()
        # enveloppe3 = sample.transaction_creer_repertoire()
        # enveloppe4 = sample.transaction_renommer_repertoire()
        # enveloppe5 = sample.transaction_deplacer_repertoire()
        # enveloppe6 = sample.transaction_renommer_fichier()
        # enveloppe7 = sample.transaction_deplacer_fichier()
        # enveloppe8 = sample.transaction_supprimer_fichier()
        # enveloppe9 = sample.transaction_supprimer_repertoire()
        # enveloppe10 = sample.transaction_commenter_repertoire()
        # enveloppe11 = sample.transaction_commenter_fichier()
        enveloppe12 = sample.transaction_changersecurite_repertoire()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

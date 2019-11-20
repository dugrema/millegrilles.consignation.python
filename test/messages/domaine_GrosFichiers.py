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
            "fuuid": "39c1e1b0-b6ee-11e9-b0cd-d30e8fab841b",
            "securite": "2.prive",
            "repertoire_uuid": '2527cadc-d8ed-11e9-8a7f-00155d011f00',
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
            "fuuid": "39c1e1b0-b6ee-11e9-b0cd-d30e8fab841b",
            "sha256": "739291ef2f7f3e0f945712112df9a62aeb2642d3828551f9fa3c95449a415e30",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.nouvelleVersion.transfertComplete',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Envoi transfert complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_creer_collection(self):
        transaction = {
            "parent_id": "019a03fd-d8f0-11e9-8a7f-00155d011f00",
            "nom": "test1",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.creerCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Envoi transfert complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_renommer_collection(self):
        transaction = {
            "uuid": "8e2cb4f4-b7bc-11e9-a426-00155d011f00",
            "nom": "sous_test_change_2",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.renommerCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_renommer_fichier(self):
        transaction = {
            "uuid": "7b3724da-0be8-11ea-bb74-00155d011f09",
            "nom": 'Bashir Bouzouka 3!',
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.renommerFichier',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_changerlibelle_fichier(self):
        transaction = {
            "uuid": "7b3724da-0be8-11ea-bb74-00155d011f09",
            "libelles": ['abcd', '1234', 'public', 'disseminer']
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.changerLibellesFichier',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Changer libelle complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_supprimer_collection(self):
        transaction = {
            "repertoire_uuid": "392405b4-b7cd-11e9-831d-00155d011f00",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.supprimerRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_commenter_collection(self):
        transaction = {
            "repertoire_uuid": "408f2b1c-b7cd-11e9-831d-00155d011f00",
            "commentaires": "J'ai un commentaire. Ye! Pis on en rajoute."
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.commenterRepertoire',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_commenter_fichier(self):
        transaction = {
            "uuid": "7b3724da-0be8-11ea-bb74-00155d011f09",
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
        # enveloppe6 = sample.transaction_renommer_fichier()
        # enveloppe11 = sample.transaction_commenter_fichier()
        enveloppe8 = sample.transaction_changerlibelle_fichier()

        # enveloppe3 = sample.transaction_creer_collection()
        # enveloppe4 = sample.transaction_renommer_collection()
        # enveloppe9 = sample.transaction_supprimer_repertoire()
        # enveloppe10 = sample.transaction_commenter_repertoire()
        # enveloppe12 = sample.transaction_changersecurite_repertoire()

        pass


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

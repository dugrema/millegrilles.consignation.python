from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMessagerie
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from threading import Event

import json
import datetime
import uuid

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

    def requete_compte_usager(self):
        requete = {'nom_usager': 'mathieu@mg-dev4.maple.maceroc.com'}
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.REQUETE_CHARGER_COMPTE])
        enveloppe = self.generateur.transmettre_requete(requete, domaine_action, 'abcd-1234', self.queue_name)

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def requete_messages_usager(self):
        requete = {'idmgs': ['29yHaJVXVZ5eCEsb7rK3iNrruDmYNh9Z2hWzNtz']}
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.REQUETE_SOMMAIRE_MESSAGES_PAR_IDMG])
        enveloppe = self.generateur.transmettre_requete(requete, domaine_action, 'abcd-1234', self.queue_name)

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def requete_messages_usager_par_source(self):
        requete = {
            'idmgs_destination': ['29yHaJVXVZ5eCEsb7rK3iNrruDmYNh9Z2hWzNtz'],
            'idmgs_source': ['XEFLEkH9vvK1zBEU8qHt2fauyfRr7CLbJEwpdTh5JWRM'],
        }
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.REQUETE_MESSAGES_USAGER_PAR_SOURCE])
        enveloppe = self.generateur.transmettre_requete(requete, domaine_action, 'abcd-1234', self.queue_name)

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_inscrire_proprietaire(self):
        transaction = {
            ConstantesMessagerie.CHAMP_NOM_USAGER: 'mathieu@mg-dev4.maple.maceroc.com',
            ConstantesMessagerie.CHAMP_IDMGS: ['29yHaJVXVZ5eCEsb7rK3iNrruDmYNh9Z2hWzNtz'],
        }
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.TRANSACTION_INSCRIRE_COMPTE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_envoyer_instantanne(self):
        transaction = {
            Constantes.DOCUMENT_INFODOC_SECURITE: Constantes.SECURITE_PRIVE,
            ConstantesMessagerie.CHAMP_IDMG_SOURCE: '29yHaJVXVZ5eCEsb7rK3iNrruDmYNh9Z2hWzNtz',
            ConstantesMessagerie.CHAMP_IDMG_DESTINATION: 'XEFLEkH9vvK1zBEU8qHt2fauyfRr7CLbJEwpdTh5JWRM',
            ConstantesMessagerie.CHAMP_MESSAGE: 'Poutine sauvage a loriginal'
        }
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.TRANSACTION_ENVOYER_MESSAGE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_marquer_message_lu(self):
        transaction = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: '6b166694-b4d8-11ea-b31e-277b4a14dd4b',
        }
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.TRANSACTION_MARQUER_MESSAGE_LU])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_supprimer_message(self, uuid_message: str):
        transaction = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_message,
        }
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.TRANSACTION_SUPPRIMER_MESSAGE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_modifier_contact(self):
        transaction = {
            ConstantesMessagerie.CHAMP_NOM_USAGER: 'mathieu@mg-dev4.maple.maceroc.com',
            ConstantesMessagerie.CHAMP_NOM_CONTACT: 'test1@mg-dev3.maple.maceroc.com',
            ConstantesMessagerie.CHAMP_NOM_USAGER_CONTACT: 'moi meme',
            ConstantesMessagerie.CHAMP_IDMGS: ['MxXNJgbQxtSVrePdMFBNqeKFtvxqDXoE8CHqD7Vkd2Vu'],
            ConstantesMessagerie.CHAMP_UUID_CONTACT: str(uuid.uuid4()),
        }
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.TRANSACTION_MODIFIER_CONTACT])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_supprimer_contact(self, uuid_contact):
        transaction = {
            ConstantesMessagerie.CHAMP_NOM_USAGER: 'mathieu@mg-dev4.maple.maceroc.com',
            ConstantesMessagerie.CHAMP_UUID_CONTACT: uuid_contact,
            ConstantesMessagerie.CHAMP_SUPPRIMER: True,
        }
        domaine_action = '.'.join([ConstantesMessagerie.DOMAINE_NOM, ConstantesMessagerie.TRANSACTION_MODIFIER_CONTACT])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def executer(self):
        # self.requete_compte_usager()
        self.requete_messages_usager()
        # self.requete_messages_usager_par_source()
        # self.transaction_inscrire_proprietaire()
        # self.transaction_envoyer_instantanne()
        # self.transaction_marquer_message_lu()
        # self.transaction_supprimer_message('1c6b139e-b4df-11ea-b31e-277b4a14dd4b')
        # self.transaction_modifier_contact()
        # self.transaction_supprimer_contact('49bc0f0d-1e89-4961-8d04-fcd4a65beb83')


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()



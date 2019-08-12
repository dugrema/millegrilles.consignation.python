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

    def requete_profil_usager(self):
        requete_profil = {
            'filtre': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_PROFIL_USAGER,
            }
        }
        requetes = {'requetes': [requete_profil]}
        enveloppe_requete = self.generateur.transmettre_requete(
            requetes, 'millegrilles.domaines.Principale', 'abcd-1234', self.queue_name)

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def envoyer_empreinte(self):

        empreinte = {
            'cle': 'absfoijfdosijfds'
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            empreinte, 'millegrilles.domaines.Principale.creerEmpreinte', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def ajouter_token(self):

        token = {
            'cle': 'cle_3'
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            token, 'millegrilles.domaines.Principale.ajouterToken', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

# --- MAIN ---
sample = MessagesSample()

# TEST
enveloppe = sample.requete_profil_usager()
# enveloppe = sample.envoyer_empreinte()
# enveloppe = sample.ajouter_token()

sample.channel.start_consuming()

# FIN TEST
sample.deconnecter()

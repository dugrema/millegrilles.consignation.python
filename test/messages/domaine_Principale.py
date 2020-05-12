import datetime, time

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPrincipale
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

    def transmettre_maj_profil_usager(self):
        fiche = {
            ConstantesPrincipale.LIBELLE_NOM: 'DugreAB',
            ConstantesPrincipale.LIBELLE_PRENOM: 'Mathieu',
            ConstantesPrincipale.LIBELLE_COURRIEL: 'jajar.jjaargh@mdugre.info',
            ConstantesPrincipale.LIBELLE_TWITTER: '@moi!',
        }

        domaine = ConstantesPrincipale.TRANSACTION_ACTION_MAJ_PROFILUSAGER
        enveloppe_val = self.generateur.soumettre_transaction(
            fiche, domaine, reply_to=self.queue_name, correlation_id='abcd'
        )

        print("Envoi maj profil usager: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_maj_profil_millegrille(self):
        fiche = {
            ConstantesPrincipale.LIBELLE_NOM_MILLEGRILLE: 'Deux Tests',
            ConstantesPrincipale.LIBELLE_LANGUE_PRINCIPALE: 'fr',
            ConstantesPrincipale.LIBELLE_LANGUE_MULTILINGUE: False,
        }

        domaine = ConstantesPrincipale.TRANSACTION_ACTION_MAJ_PROFILMILLEGRILLE
        enveloppe_val = self.generateur.soumettre_transaction(
            fiche, domaine, reply_to=self.queue_name, correlation_id='abcd'
        )

        print("Envoi maj profil usager: %s" % enveloppe_val)
        return enveloppe_val

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

    def requete_authinfo(self):
        requete_cert = {}
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert,
            ConstantesPrincipale.REQUETE_AUTHINFO_MILLEGRILLE,
            'abcd-1234',
            self.queue_name,
            securite=Constantes.SECURITE_PROTEGE,
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def executer(self):
        # sample.transmettre_maj_profil_usager()
        # sample.transmettre_maj_profil_millegrille()

        sample.requete_authinfo()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()


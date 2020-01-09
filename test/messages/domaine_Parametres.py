import datetime, time

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesParametres
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

    def maj_email_smtp_avecpassword(self):
        email_smtp_transaction = {
            ConstantesParametres.DOCUMENT_CHAMP_ACTIF: True,
            ConstantesParametres.DOCUMENT_CHAMP_HOST: 'mg-maple.local',
            ConstantesParametres.DOCUMENT_CHAMP_PORT: 443,
            ConstantesParametres.DOCUMENT_CHAMP_COURRIEL_ORIGINE: 'mathieu.dugre@mdugre.info',
            ConstantesParametres.DOCUMENT_CHAMP_COURRIEL_DESTINATIONS: 'mail@mdugre.info',
            ConstantesParametres.DOCUMENT_CHAMP_USER: 'mathieu',
            Constantes.DOCUMENT_SECTION_CRYPTE: 'du contenu crypte, mot de passe, etc.',
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            email_smtp_transaction,
            ConstantesParametres.TRANSACTION_MODIFIER_EMAIL_SMTP,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_cles(self, uuid):
        email_smtp_transaction = {
            'domaine': ConstantesParametres.DOMAINE_NOM,
            ConstantesParametres.TRANSACTION_CHAMP_MGLIBELLE: ConstantesParametres.LIBVAL_EMAIL_SMTP,
            'uuid': uuid,
        }

        routing = ConstantesParametres.TRANSACTION_CLES_RECUES

        enveloppe_val = self.generateur.soumettre_transaction(
            email_smtp_transaction,
            routing,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def maj_email_smtp_sanspassword(self):
        email_smtp_transaction = {
            ConstantesParametres.DOCUMENT_CHAMP_ACTIF: True,
            ConstantesParametres.DOCUMENT_CHAMP_HOST: 'mg-maple.local',
            ConstantesParametres.DOCUMENT_CHAMP_PORT: 443,
            ConstantesParametres.DOCUMENT_CHAMP_COURRIEL_ORIGINE: 'mathieu.dugre@mdugre.info',
            ConstantesParametres.DOCUMENT_CHAMP_COURRIEL_DESTINATIONS: 'mail@mdugre.info',
            ConstantesParametres.DOCUMENT_CHAMP_USER: 'mathieu',
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            email_smtp_transaction,
            ConstantesParametres.TRANSACTION_MODIFIER_EMAIL_SMTP,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def maj_noeud_public(self):
        transaction = {
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: 'https://localhost',
            ConstantesParametres.DOCUMENT_PUBLIQUE_MENU: [
                'fichiers',
                'messages'
            ]
        }

        domaine = ConstantesParametres.TRANSACTION_MAJ_NOEUD_PUBLIC
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, domaine, reply_to=self.queue_name, correlation_id='abcd'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def supprimer_noeud_public(self):
        transaction = {
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: 'https://localhost3',
        }

        domaine = ConstantesParametres.TRANSACTION_SUPPRIMER_NOEUD_PUBLIC
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, domaine, reply_to=self.queue_name, correlation_id='abcd'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def requete_noeud_public(self):
        requete = {
            'url_web': 'https://localhost'
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete, ConstantesParametres.REQUETE_NOEUD_PUBLIC, 'abcd-1234', self.queue_name,
            securite=Constantes.SECURITE_PUBLIC)

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete


    def executer(self):
        # uuid = self.maj_email_smtp_avecpassword()
        # enveloppe = self.transmettre_cles(uuid)
        # self.maj_noeud_public()
        self.supprimer_noeud_public()
        # self.requete_noeud_public()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()


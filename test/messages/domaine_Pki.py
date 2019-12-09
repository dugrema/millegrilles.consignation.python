# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.domaines.Pki import ConstantesPki

from threading import Event, Thread
from cryptography import x509
from cryptography.hazmat.backends import default_backend

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser(init_document=False)

class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.channel = None
        self.event_recu = Event()
        # self.thread_ioloop = Thread(target=self.run_ioloop)

        # Charger cert MaitreDesCles pour pouvoir crypter contenu a transmettre
        with open('/home/mathieu/mgdev/certs/pki.maitredescles.cert', 'rb') as certificat_pem:
            certificat_courant_pem = certificat_pem.read()
            cert = x509.load_pem_x509_certificate(
                certificat_courant_pem,
                backend=default_backend()
            )
            self.certificat_courant = cert
            self.certificat_courant_pem = certificat_courant_pem.decode('utf8')

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.executer()

    # def run_ioloop(self):
    #     self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)
        self.event_recu.set()

    def requete_verifier_cert_parfingerprint(self):
        requete_cert_maitredescles = {
            'fingerprint': '732a1171bc5b686e11b07c999cfe5fb0abb63cd9'
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            ConstantesPki.TRANSACTION_CONFIRMER_CERTIFICAT,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def executer(self):
        enveloppe = self.requete_verifier_cert_parfingerprint()


# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

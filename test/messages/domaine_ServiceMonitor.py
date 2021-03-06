# Script de test pour transmettre message de transaction

import datetime, time
import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesHebergement
from millegrilles.util.X509Certificate import EnveloppeCleCert

from threading import Event, Thread
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.channel = None
        self.event_recu = Event()
        # self.thread_ioloop = Thread(target=self.run_ioloop)

        self.queue_name = None

        self.certificat_maitredescles = None
        self.cert_maitredescles_recu = Event()

        self.mot_de_passe = 'sjdpo-1824-JWAZ'

        # Charger cert MaitreDesCles pour pouvoir crypter contenu a transmettre
        with open('/home/mathieu/mgdev/certs/pki.maitrecles.cert', 'rb') as certificat_pem:
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

        message_dict = json.loads(body)
        certificat_pem = message_dict.get('certificat')
        if certificat_pem is not None:
            cert = EnveloppeCleCert()
            cert.cert_from_pem_bytes(certificat_pem.encode('utf-8'))
            self.certificat_maitredescles = cert
            self.cert_maitredescles_recu.set()
        else:
            self.event_recu.set()
            print(json.dumps(message_dict, indent=4))

    def commande_ajouter_compte(self):
        certificat = self.certificat_courant_pem

        header = '-----BEGIN CERTIFICATE-----\n'

        certificats = certificat.split(header)[1:]
        certificats = [header + cert for cert in certificats]

        print("Transmettre certificat :\n" + certificats[0])
        for cert in certificats[1:]:
            print(cert)

        enveloppe_requete = self.generateur.transmettre_commande(
            {'certificat': certificats[0], 'chaine': certificats[1:]},
            'commande.%s' % Constantes.ConstantesServiceMonitor.COMMANDE_AJOUTER_COMPTE,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
        )

        print("Envoi commande: %s" % enveloppe_requete)
        return enveloppe_requete

    def commande_activer_hebergement(self):
        enveloppe_requete = self.generateur.transmettre_commande(
            {},
            'commande.%s' % Constantes.ConstantesServiceMonitor.COMMANDE_ACTIVER_HEBERGEMENT,
            correlation_id='abcd-1234',
            reply_to=self.queue_name
        )

        print("Envoi commande: %s" % enveloppe_requete)
        return enveloppe_requete

    def commande_desactiver_hebergement(self):
        enveloppe_requete = self.generateur.transmettre_commande(
            {},
            'commande.%s' % Constantes.ConstantesServiceMonitor.COMMANDE_DESACTIVER_HEBERGEMENT,
            correlation_id='abcd-1234',
            reply_to=self.queue_name
        )

        print("Envoi commande: %s" % enveloppe_requete)
        return enveloppe_requete

    def executer(self):
        # self.commande_creer_millegrille_hebergee()
        # self.transaction_desactiver_millegrille_hebergee()
        # self.transaction_activer_millegrille_hebergee()
        # self.commande_ajouter_compte()
        self.commande_activer_hebergement()
        # self.commande_desactiver_hebergement()


# --- MAIN ---
sample = MessagesSample()

# FIN TEST
sample.event_recu.wait(5)
try:
    sample.deconnecter()
except Exception:
    pass

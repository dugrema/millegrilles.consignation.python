from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMessagerie
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.util.Chiffrage import ChiffrerChampDict
from millegrilles.SecuritePKI import EnveloppeCertificat
from threading import Event
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import json
import datetime
import uuid
import logging
import multibase

logging.basicConfig(level=logging.ERROR)
logging.getLogger('millegrilles').setLevel(logging.INFO)
logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)

        self.queue_name = None
        self.channel = None
        self.event_recu = Event()

        with open('/home/mathieu/mgdev/certs/pki.maitrecles.cert', 'r') as fichier:
            cert_maitrecles = fichier.read()
            cert_enveloppe = EnveloppeCertificat(certificat_pem=cert_maitrecles)
            self.cert_maitrecles = cert_enveloppe.chaine_pem()

        with open(self.contexte.configuration.mq_cafile, 'r') as fichier:
            self.cacert = fichier.read()

        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        logger.debug("Channel open %s" % channel)
        channel.queue_declare('', durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        logger.debug("Queue open: %s" % str(self.queue_name))

        self.channel.basic_consume(self.queue_name, self.callbackAvecAck, auto_ack=False)

        logger.debug("Demarrer execution")
        self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        message = json.loads(str(body, 'utf-8'))
        print(json.dumps(message, indent=4))

    def verifier_preuve(self):
        requete = {
            "cles": {
                "zSEfXUEbDxbPeBxLMRChRmESn4qx26s9dWm4HSoPURfw3JrY76U5QBm4QFVG8fU78wyVX2hFvCjFjbxTu2rv8tTQVsUQfZ": "mcv9Y+kSipXenqFzLbOPGXElreTjLrjPPJwQOB4bQDjPdb7KXHCR5tj0Ob5HPkTQzRS3ItGxLUbZXLN0YZFX/CJJKiuYCwYOmW/xtWErjVas",
                "zSEfXUEcdEujRkDSkc3Cgsc3mSGBzEo8uG7mctPtgwwwbeKdfJt7vF1tVS666hE8nNeHuyDfFMb3aGckXQYm4CEjNvq27t": "mcv9Y+kSipXenqFzLbOPGXElreTjLrjPPJwQOB4bQDjPdb7KXHCR5tj0Ob5HPkTQzRS3ItGxLUbZXLN0YZFX/CJJKiuYCwYOmW/xtWErjVas",
                "z": "m"
            },
        }
        partition = 'z2i3Xjx8BhbFJ1UpmRk4WYM1z7eNrxfJpspTXBgAbtfeBN8jDZA'
        domaine = Constantes.ConstantesMaitreDesCles.DOMAINE_NOM
        action = 'verifierPreuve'
        enveloppe = self.generateur.transmettre_requete(
            requete,
            domaine=domaine, action=action, partition=partition, securite=Constantes.SECURITE_PRIVE,
            correlation_id='abcd-1234', reply_to=self.queue_name,
            ajouter_certificats=True,
        )

        logger.debug("Envoi : %s" % enveloppe)
        return enveloppe

    def executer(self):
        event = Event()
        event.wait(0.5)

        try:
            self.verifier_preuve()

        except:
            logger.exception("Erreur execution")


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(60)
sample.deconnecter()



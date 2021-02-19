# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles import Constantes
from millegrilles.domaines.Principale import ConstantesPrincipale
from millegrilles.dao.MessageDAO import JSONHelper
from millegrilles.SecuritePKI import ConstantesSecurityPki, EnveloppeCertificat
from cryptography.hazmat.primitives import serialization

from threading import Thread, Event


class BaseEnvoyerMessageEcouter(BaseCallback):

    def __init__(self):
        contexte = ContexteRessourcesMilleGrilles()
        contexte.initialiser(init_document=False)
        super().__init__(contexte)

        self.__thread_ioloop = Thread(name="MQ-ioloop", target=self.contexte.message_dao.run_ioloop)
        self.__thread_ioloop.start()
        self.generateur = self.contexte.generateur_transactions
        self.pret = Event()
        self.recu = Event()

        # Enregistrer la reply-to queue
        print("Attente du channel")
        self.contexte.message_dao.attendre_channel(5)

        self.message_dao.inscrire_topic(self.configuration.exchange_noeuds, [], self.set_cb_queue)
        # self.channel = self.message_dao.channel
        # self.channel.queue_declare(durable=True, exclusive=True, callback=self.set_cb_queue)
        self.queue_name = None
        self.pret.wait(5)

    def transmettre_certificat(self):
        cert_filename = self.configuration.pki_certfile
        with open(cert_filename, 'r') as fichier:
            cert_pem = fichier.read()
        enveloppe = EnveloppeCertificat(certificat_pem=cert_pem)

        message_evenement = ConstantesSecurityPki.DOCUMENT_EVENEMENT_CERTIFICAT.copy()
        message_evenement[ConstantesSecurityPki.LIBELLE_FINGERPRINT] = enveloppe.fingerprint
        message_evenement[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM] = str(
            enveloppe.certificat.public_bytes(serialization.Encoding.PEM), 'utf-8'
        )

        routing = '%s.%s' % (ConstantesSecurityPki.EVENEMENT_CERTIFICAT, enveloppe.fingerprint)
        self.contexte.message_dao.transmettre_message(
            message_evenement, routing
        )
        self.contexte.message_dao.transmettre_message_noeuds(
            message_evenement, routing
        )

    def set_cb_queue(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))
        # self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.pret.set()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def lire_message(self, body):
        json_helper = JSONHelper()
        message_dict = json_helper.bin_utf8_json_vers_dict(body)
        print(str(message_dict))

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        self.lire_message(body)

        self.recu.set()

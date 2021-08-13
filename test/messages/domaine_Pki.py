# Script de test pour transmettre message de transaction

import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Pki import ConstantesPki

from threading import Event, Thread

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()

class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.fichier_fuuid = "39c1e1b0-b6ee-11e9-b0cd-d30e8fab842j"

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
        print(json.dumps(json.loads(body.decode('utf-8')), indent=4))
        print("Channel : " + str(ch))
        print("Method : " + str(method))
        print("Properties : " + str(properties))
        print("Channel virtual host : " + str(ch.connection.params.virtual_host))

    def requete_cert_fingerprint(self):
        fingerprint = 'idpQSrDt2h+CE0XSJZZNPEakd3Wha+EhcD9v4VKUXSk='
        # requete_cert = {
        #     'fingerprint': fingerprint
        # }
        enveloppe_requete = self.generateur.transmettre_requete(
            dict(),
            ConstantesPki.REQUETE_CERTIFICAT_DEMANDE + '.' + fingerprint,
            'abcd-1234',
            self.queue_name,
            securite=Constantes.SECURITE_PROTEGE,
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_cert_pk(self):
        fingerprint = 'mEiArAuRl5bnjog3KF5M94sP4480FOF2JCjuMcCnqjFGI9gd'
        enveloppe_requete = self.generateur.transmettre_requete(
            {Constantes.ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE: fingerprint},
            'requete.Pki.' + ConstantesPki.REQUETE_CERTIFICAT_PAR_PK,
            'abcd-1234',
            self.queue_name,
            securite=Constantes.SECURITE_PROTEGE,
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_cert_backup(self):
        requete_cert = {}
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert,
            '%s.%s' % (ConstantesPki.DOMAINE_NOM, ConstantesPki.REQUETE_CERTIFICAT_BACKUP),
            'abcd-1234',
            self.queue_name,
            securite=Constantes.SECURITE_PROTEGE,
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_certificat(self):
        fingerprint = 'zQmfHuGwHhywuP8rX77eXkdx1gwgp4jiiWPuujQCd1Hwq9N'
        requete = {
            # 'fingerprint': 'sha256_b64:idpQSrDt2h+CE0XSJZZNPEakd3Wha+EhcD9v4VKUXSk='
        }
        domaine_action = 'requete.certificat.' + fingerprint
        self.generateur.transmettre_requete(requete, domaine_action, correlation_id='abcd', reply_to=self.queue_name)

    def executer(self):
        # self.requete_cert_backup()
        # self.requete_cert_noeuds()
        self.requete_certificat()
        # self.requete_cert_pk()


# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import json

from millegrilles.Constantes import ConstantesMaitreDesCles
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.SecuritePKI import EnveloppeCertificat

from threading import Event, Thread


class DomaineTest(BaseCallback):

    def __init__(self, connecter=True):
        contexte = ContexteRessourcesMilleGrilles()
        contexte.initialiser(connecter=connecter)

        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.channel = None
        self.event_recu = Event()
        self.messages = list()
        self.attendre_apres_recu = False

        self.event_recu_maitrecles = Event()
        self.cert_maitrecles = None

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)

        thread = Thread(name="executer", target=self.executer)
        thread.start()
        # self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        contenu = json.loads(body.decode('utf-8'))

        if properties.correlation_id == 'cert_maitre_cles':
            self.cert_maitrecles = contenu
            self.event_recu_maitrecles.set()
            return

        self.messages.append(contenu)
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(json.dumps(contenu, indent=4))
        print("Channel : " + str(ch))
        print("Method : " + str(method))
        print("Properties : " + str(properties))
        print("Channel virtual host : " + str(ch.connection.params.virtual_host))

        if self.attendre_apres_recu is False:
            self.event_recu.set()

    def get_cert_maitrecles(self):
        if self.cert_maitrecles is not None:
            return self.cert_maitrecles

        domaine_action = 'requete.MaitreDesCles.' + ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        self.generateur.transmettre_requete(dict(), domaine_action, reply_to=self.queue_name, correlation_id='cert_maitre_cles')
        self.event_recu_maitrecles.wait(2)

        return self.cert_maitrecles

    def get_enveloppe_maitrecles(self):
        message = self.get_cert_maitrecles()
        certificat_pem = ''.join(message['certificat'])
        enveloppe = EnveloppeCertificat(certificat_pem=certificat_pem)
        return enveloppe

    def executer(self):
        raise NotImplementedError()

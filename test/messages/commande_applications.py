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

        self.channel = None
        self.event_recu = Event()

        self.noeud_id = '1c0d5eb2-f820-4220-ae3a-28959d59eb44'

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

    # def installer_application_blynk(self):
    #     commande = {
    #         'nom_application': 'blynk',
    #         'configuration': blynk_app,
    #     }
    #     domaineAction = 'commande.servicemonitor.%s.%s' % (
    #         uuid_service_monitor, Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION)
    #
    #     enveloppe = self.generateur.transmettre_commande(
    #         commande,
    #         domaineAction,
    #         correlation_id='abcd-1234',
    #         reply_to=self.queue_name,
    #         exchange=Constantes.SECURITE_PROTEGE
    #     )
    #
    #     print("Envoi : %s" % enveloppe)
    #     return enveloppe

    def backup_application(self):
        commande = {
            'nom_application': 'redmine_mariadb',
            # 'nom_application': 'blynk',
        }
        domaineAction = 'commande.servicemonitor.%s.%s' % (
            self.noeud_id, Constantes.ConstantesServiceMonitor.COMMANDE_BACKUP_APPLICATION)

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def backup_applications(self):
        commande = {}
        domaineAction = Constantes.ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE_GLOBAL

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def restore_application(self):
        commande = {
            # 'nom_application': 'redmine_mariadb',
            'nom_application': 'blynk',
        }
        domaineAction = 'commande.servicemonitor.%s.%s' % (
            self.noeud_id, Constantes.ConstantesServiceMonitor.COMMANDE_RESTORE_APPLICATION)

        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaineAction,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.SECURITE_PROTEGE
        )

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def executer(self):
        # self.backup_application()
        self.backup_applications()
        # self.restore_application()


# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()

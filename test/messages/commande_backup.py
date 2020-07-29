# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import datetime
import time
import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesDomaines, ConstantesBackup
from millegrilles.domaines.Principale import ConstantesPrincipale
from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

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

    def commande_regenerer(self):
        domaines = [
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace('_DOMAINE_', 'Annuaire'),
            # 'commande.millegrilles.domaines.Backup.%s' % ConstantesDomaines.COMMANDE_REGENERER,
            # 'commande.millegrilles.domaines.GrosFichiers.%s' % ConstantesDomaines.COMMANDE_REGENERER,
            # 'commande.millegrilles.domaines.MaitreDesCles.%s' % ConstantesDomaines.COMMANDE_REGENERER,
            # 'commande.millegrilles.domaines.Parametres.%s' % ConstantesDomaines.COMMANDE_REGENERER,
            # # 'commande.millegrilles.domaines.Pki.%s' % ConstantesDomaines.COMMANDE_REGENERER,
            # 'commande.millegrilles.domaines.Plume.%s' % ConstantesDomaines.COMMANDE_REGENERER,
            # 'commande.millegrilles.domaines.Principale.%s' % ConstantesDomaines.COMMANDE_REGENERER,
            # 'commande.millegrilles.domaines.SenseursPassifs.%s' % ConstantesDomaines.COMMANDE_REGENERER,
            # 'commande.millegrilles.domaines.Taches.%s' % ConstantesDomaines.COMMANDE_REGENERER,
        ]

        declencheur = {
            ConstantesBackup.LIBELLE_HEURE: datetime.datetime.utcnow().timestamp(),
            ConstantesBackup.LIBELLE_SECURITE: '1.public',
        }
        for domaine in domaines:
            enveloppe_val = self.generateur.transmettre_commande(
                declencheur, domaine, reply_to=self.queue_name, correlation_id='reply_regenerer')
            print("Commande regenerer domaine %s : %s" % (domaine, enveloppe_val))

    def trigger_backup_global(self):
        timestamp_courant = datetime.datetime.utcnow()

        commande_backup_quotidien = {
            ConstantesBackup.LIBELLE_HEURE: int(timestamp_courant.timestamp()),
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_quotidien,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE_GLOBAL,
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_horaire'
        )

    def trigger_backup_reset_global(self):
        timestamp_courant = datetime.datetime.utcnow()

        commande_backup_quotidien = {
            ConstantesBackup.LIBELLE_HEURE: int(timestamp_courant.timestamp()),
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_quotidien,
            ConstantesBackup.COMMANDE_BACKUP_RESET_GLOBAL,
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_reset'
        )

    def executer(self):
        # sample.commande_regenerer()
        sample.trigger_backup_global()
        # sample.trigger_backup_reset_global()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()
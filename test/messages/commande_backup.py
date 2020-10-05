# Script de test pour transmettre message de transaction
import datetime
import time
import json
import requests
import tarfile
import logging
import sys

from io import BufferedReader, RawIOBase

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesDomaines, ConstantesBackup
from millegrilles.domaines.Principale import ConstantesPrincipale
from threading import Thread, Event
from millegrilles.util.BackupModule import ArchivesBackupParser

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class WrapperDownload(RawIOBase):

    def __init__(self, generator):
        super().__init__()
        self.__generator = generator

    def read(self, *args, **kwargs):  # real signature unknown
        print(args)
        for data in self.__generator:
            return data

    def read1(self, *args, **kwargs):  # real signature unknown
        """
        Read at most size bytes, returned as a bytes object.

        If the size argument is negative or omitted, read until EOF is reached.
        Return an empty bytes object at EOF.
        """
        pass

    def readable(self, *args, **kwargs):  # real signature unknown
        """ Returns True if the IO object can be read. """
        return True

    # def seek(self, *args, **kwargs):
    #     print("Seek " + str(args))
    #     return 1

    def seekable(self):
        return False

    # def read(self):
    #     if self.__iter is not None:
    #         return self.__iter.__next__()
    #     else:
    #         self.__iter = self.__generator.__iter__()
    #         return self.__iter.next()


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

    def requete_backup_dernierhoraire(self):
        requete = {
            'domaine': Constantes.ConstantesMaitreDesCles.DOMAINE_NOM,
        }
        self._contexte.generateur_transactions.transmettre_requete(
            requete,
            ConstantesBackup.REQUETE_BACKUP_DERNIERHORAIRE,
            reply_to=self.queue_name,
            correlation_id='requete'
        )

    def trigger_backup_maitrecles(self):
        timestamp_courant = datetime.datetime.utcnow()

        commande_backup_quotidien = {
            ConstantesBackup.LIBELLE_HEURE: int(timestamp_courant.timestamp()),
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_quotidien,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace('_DOMAINE_', Constantes.ConstantesMaitreDesCles.DOMAINE_NOM),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_horaire'
        )

    def trigger_backup_grosfichiers(self):
        timestamp_courant = datetime.datetime.utcnow()

        commande_backup_quotidien = {
            ConstantesBackup.LIBELLE_HEURE: int(timestamp_courant.timestamp()),
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_quotidien,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace('_DOMAINE_',
                                                                        Constantes.ConstantesGrosFichiers.DOMAINE_NOM),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_horaire'
        )

    def trigger_backup_snapshot_maitredescles(self):
        commande_backup_snapshot = {
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_snapshot,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_SNAPSHOT.replace('_DOMAINE_',
                                                                         Constantes.ConstantesMaitreDesCles.DOMAINE_NOM),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_snapshot'
        )

    def trigger_backup_snapshot_global(self):
        commande_backup_snapshot = {
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_snapshot,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_SNAPSHOT.replace('_DOMAINE_', 'global'),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_snapshot'
        )

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

    def preparer_restauration(self):
        commande = {
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande,
            ConstantesBackup.COMMANDE_BACKUP_PREPARER_RESTAURATION,
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_reset'
        )

    def requete_get_backups_horaire(self):
        url = 'https://mg-dev4:3021/fichiers/backup/restaurerDomaine/MaitreDesCles'
        cacert = self.configuration.mq_cafile
        certkey = (self.configuration.mq_certfile, self.configuration.mq_keyfile)
        resultat = requests.get(url, verify=cacert, cert=certkey, stream=True)
        print("Response code : %d" % resultat.status_code)

        if resultat.status_code == 200:
            print(resultat.headers)
            # wrapper = WrapperDownload(resultat.iter_content(chunk_size=512 * 1024))
            # tar_stream = tarfile.open(fileobj=wrapper, mode='r|')
            # for tar_info in tar_stream:
            #     name = tar_info.name.split('/')[-1]
            #     with open('/home/mathieu/tmp/backup_test/' + name, 'wb') as fichier:
            #         print(tar_info.name)
            #         fo = tar_stream.extractfile(tar_info)
            #         fichier.write(fo.read())

            parser = ArchivesBackupParser(
                resultat.iter_content(chunk_size=4 * 1024))  #, '/home/mathieu/tmp/backup_test/')
            parser.parse_tar_stream()

        resultat.close()

    def executer(self):
        # sample.requete_backup_dernierhoraire()
        # sample.commande_regenerer()
        # sample.trigger_backup_reset_global()
        # sample.trigger_backup_global()
        # sample.trigger_backup_maitrecles()
        # sample.trigger_backup_grosfichiers()
        # sample.trigger_backup_snapshot_maitredescles()
        # sample.trigger_backup_snapshot_global()

        # sample.preparer_restauration()
        sample.requete_get_backups_horaire()


# --- MAIN ---
logging.basicConfig()
logging.getLogger('millegrilles').setLevel(logging.DEBUG)
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(100)
sample.deconnecter()
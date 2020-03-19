import datetime
import time
import json
import lzma
import logging
import requests
import ssl
import hashlib
import binascii
from threading import Thread, Event
from os import listdir, path
from pymongo.errors import DuplicateKeyError

from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes, ConstantesGrosFichiers
from millegrilles.util.JSONMessageEncoders import BackupFormatEncoder, decoder_backup

from millegrilles.Domaines import HandlerBackupDomaine
from millegrilles.domaines.GrosFichiers import HandlerBackupGrosFichiers

contexte = ContexteRessourcesDocumentsMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger.setLevel(logging.DEBUG)

        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.handler_backup = HandlerBackupDomaine(self.contexte)
        self.handler_grosfichiers = HandlerBackupGrosFichiers(self.contexte)

        self.channel = None
        self.event_recu = Event()

        self.idmg = 'bKKwtXC68HR4TPDzet6zLVq2wPJfc9RiiYLuva'

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
        self.__logger.debug(str(body))

    def executer(self):
        try:
            self.backup_domaine_senseurpassifs()
            # self.backup_domaine_grosfichiers()
            # self.restore_horaire_domaine_senseurspassifs()
        finally:
            self.event_recu.set()  # Termine

    def backup_transactions_senseurspassifs_testinit(self):
        coltrans = self.contexte.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        filtre = {}
        curseur = coltrans.find(filtre)

        with lzma.open('/tmp/senseurspassifs.json.xz', 'wt') as fichier:
            for transaction in curseur:
                json.dump(transaction, fichier, sort_keys=True, ensure_ascii=True, cls=BackupFormatEncoder)
                # Une transaction par ligne
                fichier.write('\n')
                # json_transaction = self.__json_helper.dict_vers_json(transaction)
                # self.__logger.debug("Transaction %s" % json_transaction)

    def backup_domaine_senseurpassifs(self):
        nom_collection_mongo = SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM
        heure_courante = datetime.datetime.utcnow()
        heure = datetime.datetime(year=2020, month=2, day=6, hour=21, tzinfo=datetime.timezone.utc)
        # heure = datetime.datetime(year=heure_courante.year, month=heure_courante.month, day=heure_courante.day, hour=heure_courante.hour, tzinfo=datetime.timezone.utc)
        heure = heure - datetime.timedelta(hours=1)
        self.__logger.debug("Faire backup horaire de %s" % str(heure))
        self.handler_backup.backup_domaine(nom_collection_mongo, self.idmg, heure, nom_collection_mongo)

    def backup_domaine_grosfichiers(self):
        nom_collection_mongo = ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM
        heure_courante = datetime.datetime.utcnow()
        # heure = datetime.datetime(year=2020, month=3, day=15, hour=22, tzinfo=datetime.timezone.utc)
        heure = datetime.datetime(year=heure_courante.year, month=heure_courante.month, day=heure_courante.day, hour=heure_courante.hour, tzinfo=datetime.timezone.utc)
        heure = heure - datetime.timedelta(hours=1)
        self.__logger.debug("Faire backup horaire de %s" % str(heure))
        self.handler_grosfichiers.backup_domaine(nom_collection_mongo, self.idmg, heure, nom_collection_mongo)

    def restore_horaire_domaine_senseurspassifs(self):
        nom_collection_mongo = SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM
        # path_fichier = '/tmp/mgbackup/senseurspassifs_2020010619.json.xz'
        path_folder = '/tmp/mgbackup'

        for fichier in listdir(path_folder):
            path_complet = path.join(path_folder, fichier)
            if path.isfile(path_complet) and fichier.startswith('senseurspassifs') and fichier.endswith('.json.xz'):
                self.restore_horaire_domaine(nom_collection_mongo, self.idmg, path_complet)

    def restore_horaire_domaine(self, nom_collection_mongo: str, idmg: str, path_fichier: str):
        coltrans = self.contexte.document_dao.get_collection(nom_collection_mongo)

        with lzma.open(path_fichier, 'rt') as fichier:
            for line in fichier:
                transaction = json.loads(line, object_hook=decoder_backup)

                self.__logger.debug("Transaction : %s" % str(transaction))
                try:
                    coltrans.insert(transaction)
                except DuplicateKeyError:
                    self.__logger.warning("Transaction existe deja : %s" % transaction['en-tete']['uuid-transaction'])


# -------
logging.basicConfig()
logging.getLogger('millegrilles.Domaines.HandlerBackupDomaine').setLevel(logging.DEBUG)
sample = MessagesSample()

# TEST
# sample.executer()

# FIN TEST
sample.event_recu.wait(200)
sample.deconnecter()

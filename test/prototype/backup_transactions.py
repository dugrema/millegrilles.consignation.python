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

        # Preparer URL de connexion a consignationfichiers
        self.url_consignationfichiers = 'https://%s:%s' % (
            self._contexte.configuration.serveur_consignationfichiers_host,
            self._contexte.configuration.serveur_consignationfichiers_port,
        )

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
            # self.backup_domaine_senseurpassifs()
            # self.backup_domaine_grosfichiers()

            # self.restore_domaine(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
            self.restore_domaine(ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM)

            # self.reset_evenements()
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
        # heure = datetime.datetime(year=2020, month=3, day=6, hour=21, tzinfo=datetime.timezone.utc)
        heure = datetime.datetime(year=heure_courante.year, month=heure_courante.month, day=heure_courante.day, hour=heure_courante.hour, tzinfo=datetime.timezone.utc)
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

    def restore_domaine(self, nom_collection_mongo):

        path_folder = '/tmp/mgbackup'

        self.handler_grosfichiers.restaurer_domaines_horaires(nom_collection_mongo)

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

    def reset_evenements(self):
        col_grosfichiers = self.contexte.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM)
        col_senseurspassifs = self.contexte.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        evenement_libelle_backup = '_evenements.%s.backup_horaire' % self.idmg
        evenement_libelle_restauree = '_evenements.%s.transaction_restauree' % self.idmg
        ops = {'$unset': {evenement_libelle_backup: True, evenement_libelle_restauree: True}}

        col_grosfichiers.update_many({}, ops)
        col_senseurspassifs.update_many({}, ops)

# -------
logging.basicConfig()
logging.getLogger('millegrilles.Domaines.HandlerBackupDomaine').setLevel(logging.DEBUG)
sample = MessagesSample()

# TEST
# sample.executer()

# FIN TEST
sample.event_recu.wait(200)
sample.deconnecter()

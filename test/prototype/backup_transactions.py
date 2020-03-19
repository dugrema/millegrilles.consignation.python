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

        # nom_collection_mongo = SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM
        # nom_collection_mongo = ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

        data = {
            'domaine': nom_collection_mongo
        }

        path_folder = '/tmp/mgbackup'

        with requests.get(
                '%s/backup/liste/backups_horaire' % self.url_consignationfichiers,
                data=data,
                verify=self._contexte.configuration.mq_cafile,
                cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile)
        ) as r:

            if r.status_code == 200:
                reponse_json = json.loads(r.text)
            else:
                raise Exception("Erreur chargement liste backups horaire")

        self.__logger.debug("Reponse liste backups horaire:\n" + json.dumps(reponse_json, indent=4))

        for heure, backups in reponse_json['backupsHoraire'].items():
            self.__logger.debug("Telechargement fichiers backup %s" % heure)
            path_fichier_transaction = backups['transactions']
            nom_fichier_transaction = path.basename(path_fichier_transaction)

            with requests.get(
                    '%s/backup/transactions/%s' % (self.url_consignationfichiers, path_fichier_transaction),
                    verify=self._contexte.configuration.mq_cafile,
                    cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            ) as r:

                r.raise_for_status()

                # Sauvegarder le fichier
                with open(path.join(path_folder, nom_fichier_transaction), 'wb') as fichier:
                    for chunk in r.iter_content(chunk_size=8192):
                        fichier.write(chunk)

            path_fichier_catalogue = backups['catalogue']
            nom_fichier_catalogue = path.basename(path_fichier_catalogue)

            # Verifier l'integrite du fichier de transactions
            with lzma.open(path.join(path_folder, nom_fichier_catalogue), 'rt') as fichier:
                catalogue = json.load(fichier, object_hook=decoder_backup)

            self.__logger.debug("Verifier signature catalogue %s\n%s" % (nom_fichier_catalogue, catalogue))
            self._contexte.verificateur_transaction.verifier(catalogue)

            with requests.get(
                    '%s/backup/catalogues/%s' % (self.url_consignationfichiers, path_fichier_catalogue),
                    verify=self._contexte.configuration.mq_cafile,
                    cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            ) as r:

                r.raise_for_status()

                # Sauvegarder le fichier
                with open(path.join(path_folder, nom_fichier_catalogue), 'wb') as fichier:
                    for chunk in r.iter_content(chunk_size=8192):
                        fichier.write(chunk)

            # Catalogue ok, on verifie fichier de transactions
            self.__logger.debug("Verifier SHA512 sur le fichier de transactions %s" % nom_fichier_transaction)
            transactions_sha512 = catalogue['transactions_sha512']
            sha512 = hashlib.sha512()
            with open(path.join(path_folder, nom_fichier_transaction), 'rb') as fichier:
                sha512.update(fichier.read())
            sha512_digest_calcule = sha512.hexdigest()

            if transactions_sha512 != sha512_digest_calcule:
                raise Exception(
                    "Le fichier de transactions %s est incorrect, SHA512 ne correspond pas a celui du catalogue" %
                    nom_fichier_transaction
                )

        nom_collection_mongo = SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM
        path_fichier = '/tmp/mgbackup/senseurspassifs_2020010619.json.xz'

        # for fichier in listdir(path_folder):
        #     path_complet = path.join(path_folder, fichier)
        #     if path.isfile(path_complet) and fichier.startswith('senseurspassifs') and fichier.endswith('.json.xz'):
        #         self.restore_horaire_domaine(nom_collection_mongo, self.idmg, path_complet)

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

        evenement_libelle = '_evenements.%s.backup_horaire' % self.idmg
        filtre = {evenement_libelle: {'$exists': True}}
        ops = {'$unset': {evenement_libelle: True}}

        col_grosfichiers.update_many(filtre, ops)
        col_senseurspassifs.update_many(filtre, ops)

# -------
logging.basicConfig()
logging.getLogger('millegrilles.Domaines.HandlerBackupDomaine').setLevel(logging.DEBUG)
sample = MessagesSample()

# TEST
# sample.executer()

# FIN TEST
sample.event_recu.wait(200)
sample.deconnecter()

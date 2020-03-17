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


contexte = ContexteRessourcesDocumentsMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger.setLevel(logging.DEBUG)

        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

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
        # heure = datetime.datetime(year=2020, month=1, day=6, hour=19)
        heure_courante = datetime.datetime.utcnow()
        # heure = datetime.datetime(year=heure_courante.year, month=heure_courante.month, day=heure_courante.day, hour=heure_courante.hour, tzinfo=datetime.timezone.utc)
        heure = datetime.datetime(year=2020, month=1, day=6, hour=21, tzinfo=datetime.timezone.utc)
        heure = heure - datetime.timedelta(hours=1)
        self.__logger.debug("Faire backup horaire de %s" % str(heure))
        self.backup_domaine(nom_collection_mongo, self.idmg, heure)

    def backup_domaine_grosfichiers(self):
        nom_collection_mongo = SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM
        # heure = datetime.datetime(year=2020, month=1, day=6, hour=19)
        heure_courante = datetime.datetime.utcnow()
        heure = datetime.datetime(year=heure_courante.year, month=heure_courante.month, day=heure_courante.day, hour=heure_courante.hour, tzinfo=datetime.timezone.utc)
        heure = heure - datetime.timedelta(hours=1)
        self.__logger.debug("Faire backup horaire de %s" % str(heure))
        self.backup_domaine(nom_collection_mongo, self.idmg, heure)

    def backup_domaine(self, nom_collection_mongo, idmg, heure):
        # Verifier s'il y a des transactions qui n'ont pas ete traitees avant la periode actuelle
        filtre_verif_transactions_anterieures = {
            '_evenements.transaction_complete': True,
            '_evenements.%s.transaction_traitee' % idmg: {'$lt': heure}
        }
        regroupement_periode = {
            'year': {'$year': '$_evenements.%s.transaction_traitee' % idmg},
            'month': {'$month': '$_evenements.%s.transaction_traitee' % idmg},
            'day': {'$dayOfMonth': '$_evenements.%s.transaction_traitee' % idmg},
            'hour': {'$hour': '$_evenements.%s.transaction_traitee' % idmg},
        }
        regroupement = {
            '_id': {
                'timestamp': {
                    '$dateFromParts': regroupement_periode
                },
            },
        }
        sort = {'_id': 1}
        operation = [
            {'$match': filtre_verif_transactions_anterieures},
            {'$group': regroupement},
            {'$sort': sort},
        ]
        hint = {
            '_evenements.transaction_complete': 1,
            '_evenements.%s.transaction_traitee' % idmg: 1,
        }
        coltrans = self.contexte.document_dao.get_collection(nom_collection_mongo)

        for transanter in coltrans.aggregate(operation):
            self.__logger.debug("Vieille transaction : %s" % str(transanter))
            heure_anterieure = transanter['_id']['timestamp']

            # Creer le fichier de backup
            dependances_backup = self.backup_horaire_domaine(nom_collection_mongo, idmg, heure_anterieure)
            path_fichier_backup = dependances_backup['path_fichier_backup']
            nom_fichier_backup = path.basename(path_fichier_backup)

            self.__logger.debug("Information fichier backup:\n%s" % json.dumps(dependances_backup, indent=4))

            # Transferer vers consignation_fichier
            data = {
                'timestamp_backup': int(heure_anterieure.timestamp()),
                'fuuid_grosfichiers': json.dumps(dependances_backup['fuuid_grosfichiers'])
            }

            with open(path_fichier_backup, 'rb') as fichier:
                files = {
                    'fichiers_backup': (nom_fichier_backup, fichier, 'application/x-xz')
                }
                r = requests.put(
                    'https://mg-dev3:3003/backup/domaine/%s' % nom_fichier_backup,
                    data=data,
                    files=files,
                    verify=self.configuration.mq_cafile,
                    cert=(self.configuration.mq_certfile, self.configuration.mq_keyfile)
                )
            reponse_json = json.loads(r.text)
            self.__logger.debug("Reponse backup\nHeaders: %s\nData: %s" % (r.headers, str(reponse_json)))

            # Verifier si le SHA512 du fichier de backup recu correspond a celui calcule localement
            if reponse_json['fichiersDomaines'][nom_fichier_backup] != dependances_backup['sha512_fichier_backup']:
                raise ValueError("Le SHA512 du fichier de backup ne correspond pas a celui recu de consignationfichiers")

    def backup_horaire_domaine(self, nom_collection_mongo: str, idmg: str, heure: datetime):
        heure_str = heure.strftime("%Y%m%d%H")
        heure_fin = heure + datetime.timedelta(hours=1)
        self.__logger.debug("Backup collection %s entre %s et %s" % (nom_collection_mongo, heure, heure_fin))

        coltrans = self.contexte.document_dao.get_collection(nom_collection_mongo)
        filtre = {
            '_evenements.transaction_complete': True,
            '_evenements.%s.transaction_traitee' % idmg: {
                '$gte': heure,
                '$lt': heure_fin
            }
        }
        sort = [
            ('_evenements.%s.transaction_traitee' % idmg, 1)
        ]

        curseur = coltrans.find(filtre, sort=sort)

        path_fichier_backup = '/tmp/mgbackup/senseurspassifs_%s.json.xz' % heure_str

        dependances_backup = {
            'path_fichier_backup': path_fichier_backup,

            # Conserver la liste des certificats racine, intermediaire et noeud necessaires pour
            # verifier toutes les transactions de ce backup
            'certificats_racine': list(),
            'certificats_intermediaires': list(),
            'certificats': list(),

            # Conserver la liste des grosfichiers requis pour ce backup
            'fuuid_grosfichiers': list(),
        }

        with lzma.open(path_fichier_backup, 'wt') as fichier:
            for transaction in curseur:
                json.dump(transaction, fichier, sort_keys=True, ensure_ascii=True, cls=BackupFormatEncoder)

                # Une transaction par ligne
                fichier.write('\n')

        # Calculer SHA-512 du fichier de backup
        sha512 = hashlib.sha512()
        with open(path_fichier_backup, 'rb') as fichier:
            sha512.update(fichier.read())
        sha512_digest = sha512.hexdigest()
        dependances_backup['sha512_fichier_backup'] = sha512_digest

        return dependances_backup

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
sample = MessagesSample()

# TEST
# sample.executer()

# FIN TEST
sample.event_recu.wait(200)
sample.deconnecter()

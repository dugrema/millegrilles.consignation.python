import datetime
import time
import json
import lzma
import logging
from threading import Thread, Event
from os import listdir, path
from pymongo.errors import DuplicateKeyError

from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes
from millegrilles.util.JSONMessageEncoders import BackupFormatEncoder


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
            # self.backup_domaine_senseurpassifs()
            self.restore_horaire_domaine_senseurspassifs()
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
            '_evenements.%s.transaction_traitee' % idmg: 1
        }
        coltrans = self.contexte.document_dao.get_collection(nom_collection_mongo)

        # projection = [
        #     '_evenements.%s.transaction_traitee' % idmg
        # ]
        # for transanter in coltrans.find(filtre_verif_transactions_anterieures, projection=projection):
        #     self.__logger.debug("Vieille transaction : %s" % str(transanter))

        for transanter in coltrans.aggregate(operation, hint=hint):
            self.__logger.debug("Vieille transaction : %s" % str(transanter))
            heure_anterieure = transanter['_id']['timestamp']
            self.backup_horaire_domaine(nom_collection_mongo, idmg, heure_anterieure)

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
        with lzma.open('/tmp/mgbackup/senseurspassifs_%s.json.xz' % heure_str, 'wt') as fichier:
            for transaction in curseur:
                json.dump(transaction, fichier, sort_keys=True, ensure_ascii=True, cls=BackupFormatEncoder)

                # Une transaction par ligne
                fichier.write('\n')

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
                transaction = json.loads(line)

                # Restaurer les dates dans l'element _evenements
                evenements = transaction['_evenements']
                evenements['_estampille'] = datetime.datetime.fromtimestamp(evenements['_estampille'] / 1000)

                for idmg, events_par_mg in evenements.items():
                    if not idmg.startswith('_') and isinstance(events_par_mg, dict):
                        dates_corrigees = dict()
                        for event_name, ts_int in events_par_mg.items():
                            dates_corrigees[event_name] = datetime.datetime.fromtimestamp(ts_int / 1000)
                        evenements[idmg] = dates_corrigees

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

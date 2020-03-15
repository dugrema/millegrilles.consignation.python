import datetime
import time
import json
import lzma
import logging
from threading import Thread, Event

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
        self.__logger.debug(str(body))

    def executer(self):
        # self.backup_transactions_senseurspassifs()
        self.backup_horaire_domaine_senseurpassifs()

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

    def backup_horaire_domaine_senseurpassifs(self):
        nom_collection_mongo = SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM
        idmg = 'bKKwtXC68HR4TPDzet6zLVq2wPJfc9RiiYLuva'
        heure = datetime.datetime(year=2020, month=1, day=6, hour=19)
        self.backup_horaire_domaine(nom_collection_mongo, idmg, heure)

    def backup_horaire_domaine(self, nom_collection_mongo, idmg, heure):
        delta = datetime.timedelta(hours=1)
        heure_fin = heure + delta
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
        with lzma.open('/tmp/senseurspassifs.json.xz', 'wt') as fichier:
            for transaction in curseur:
                json.dump(transaction, fichier, sort_keys=True, ensure_ascii=True, cls=BackupFormatEncoder)

                # Une transaction par ligne
                fichier.write('\n')


# -------
logging.basicConfig()
sample = MessagesSample()

# TEST
sample.executer()

# FIN TEST
# sample.event_recu.wait(10)
sample.deconnecter()

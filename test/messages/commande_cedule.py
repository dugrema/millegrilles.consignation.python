# Script de test pour transmettre message de transaction
import datetime
import time
import json
import requests
import tarfile
import logging
import sys

from io import BufferedReader, RawIOBase
from uuid import uuid1

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
        self.event_recu.set()

    def evenement_horaire(self):
        timestamp_courant = datetime.datetime.utcnow()

        event_cedule = {
            "date_string": "2021-10-06T22:11:02.102797561+00:00",
            "estampille": int(timestamp_courant.timestamp()),
            "flag_annee": False,
            "flag_heure": True,
            "flag_jour": False,
            "flag_mois": False,
            "flag_semaine": False
        }
        self._contexte.generateur_transactions.emettre_message(
            event_cedule,
            'evenement.global.cedule',
            exchanges=[Constantes.SECURITE_SECURE],
            correlation_id='cedule_horaire',
            action='cedule',
            ajouter_certificats=True
        )

    def executer(self):
        sample.evenement_horaire()


# --- MAIN ---
logging.basicConfig()
logging.getLogger('millegrilles').setLevel(logging.DEBUG)
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(240)

# Attendre de recevoir tous les messages
while sample.event_recu.is_set():
    sample.event_recu.clear()
    sample.event_recu.wait(5)

sample.deconnecter()

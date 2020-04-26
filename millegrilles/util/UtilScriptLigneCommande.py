# Module avec des utilitaires pour la ligne de commande.

import argparse
import signal
import logging
import time
import sys
import threading
import os
import json
import tempfile

from threading import Event

from millegrilles import Constantes
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.SecuritePKI import GestionnaireEvenementsCertificat


class ModeleConfiguration:

    def __init__(self):
        self._logger = logging.getLogger('%s' % self.__class__.__name__)
        self._logger.setLevel(logging.INFO)
        self._contexte = ContexteRessourcesDocumentsMilleGrilles()
        self.parser = None  # Parser de ligne de commande
        self.args = None  # Arguments de la ligne de commande

        self.__fermeture_event = Event()

        self.__certificat_event_handler: GestionnaireEvenementsCertificat = None
        self.__channel = None

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        # Gerer les signaux OS, permet de deconnecter les ressources au besoin
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

        self._contexte.initialiser(
            init_document=init_document,
            init_message=init_message,
            connecter=connecter
        )

        if init_message:
            self._contexte.message_dao.register_channel_listener(self)

        self.initialiser_2(contexte=self._contexte)

    def initialiser_2(self, contexte):
        if contexte is not None:
            self._contexte = contexte
        self.__certificat_event_handler = GestionnaireEvenementsCertificat(self._contexte)

    def on_channel_open(self, channel):
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel
        self.__certificat_event_handler.initialiser()

    def on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self._logger.warning("MQ Channel ferme")
        if not self.__fermeture_event.is_set():
            try:
                self.contexte.message_dao.enter_error_state()
            except Exception:
                # Erreur d'activation du error state, la connexion ne peut pas etre reactivee
                self._logger.exception("Erreur fermeture channel")
                self.__fermeture_event.set()  # S'assurer que la fermeture est en cours

    def __on_return(self, channel, method, properties, body):
        pass

    def configurer_parser(self):
        self.parser = argparse.ArgumentParser(description="Fonctionnalite MilleGrilles")

        self.parser.add_argument(
            '--debug', action="store_true", required=False,
            help="Active le debugging (logger, tres verbose)"
        )

        self.parser.add_argument(
            '--info', action="store_true", required=False,
            help="Afficher davantage de messages (verbose)"
        )

    def print_help(self):
        self.parser.print_help()

    def exit_gracefully(self, signum=None, frame=None):
        self.__fermeture_event.set()
        self.deconnecter()

    def parse(self):
        self.args = self.parser.parse_args()

    def executer(self):
        raise NotImplemented("Cette methode doit etre redefinie")

    def connecter(self):
        if self._contexte.message_dao is not None:
            self._contexte.message_dao.connecter()

        if self._contexte.document_dao is not None:
            self._contexte.document_dao.connecter()

    def deconnecter(self):
        try:
            if self._contexte.message_dao is not None:
                self._contexte.message_dao.deconnecter()
        except Exception:
            self._logger.warning("Erreur fermeture message_dao")

        try:
            if self._contexte.document_dao is not None:
                self._contexte.document_dao.deconnecter()
        except Exception:
            self._logger.warning("Erreur fermeture document_dao")

    def set_logging_level(self):
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
        elif self.args.info:
            self._logger.setLevel(logging.INFO)
            logging.getLogger('millegrilles').setLevel(logging.INFO)

    def main(self):

        code_retour = 0

        try:
            # Preparer logging
            logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.WARNING)
            # logging.getLogger('millegrilles.dao.MessageDAO').setLevel(logging.INFO)
            self._logger.info("\n-----------\n\n-----------")
            self._logger.info("Demarrage de %s en cours\n-----------" % self.__class__.__name__)

            # Faire le parsing des arguments pour verifier s'il en manque
            self.configurer_parser()
            self.parse()

            self.set_logging_level()

            self._logger.info("Initialisation")
            self.initialiser()  # Initialiser les ressources

            self._logger.info("Debut execution")
            self.executer()  # Executer le download et envoyer message
            self.__fermeture_event.set()
            self._logger.info("Fin execution " + self.__class__.__name__)

        except Exception as e:
            # print("MAIN: Erreur fatale, voir log. Erreur %s" % str(e))
            self._logger.exception("MAIN: Erreur")
            code_retour = 1

        finally:
            self.exit_gracefully()

        self._logger.info("Main terminee, finalisation et sortie.")
        try:
            self.__finalisation()
        finally:
            sys.exit(code_retour)

    def __finalisation(self):
        time.sleep(0.2)

        if threading.active_count() > 1:
            ok_threads = ['MainThread', 'pymongo_kill_cursors_thread']
            for thread in threading.enumerate():
                if thread.name not in ok_threads:
                    self._logger.error("Thread ouverte apres demande de fermeture: %s" % thread.name)

            time.sleep(5)
            for thread in threading.enumerate():
                if thread.name not in ok_threads:
                    if not thread.isDaemon():
                        self._logger.warning("Non-daemon thread encore ouverte apres demande de fermeture: %s" % thread.name)

    @property
    def contexte(self) -> ContexteRessourcesDocumentsMilleGrilles:
        return self._contexte

    @property
    def channel(self):
        return self.__channel

    @staticmethod
    def preparer_mongo_keycert():
        json_file = os.getenv('MG_CONFIG_JSON')
        if json_file:
            with open(json_file, 'r') as fichier:
                params = json.load(fichier)
        else:
            params = os.environ

        certfile = params['MG_MQ_CERTFILE']
        keyfile = params['MG_MQ_KEYFILE']

        mongo_keycert_handle, mongo_keycert = tempfile.mkstemp(dir='/tmp', text=True)
        try:
            with open(keyfile, 'rb') as fichiers:
                os.write(mongo_keycert_handle, fichiers.read())
            with open(certfile, 'rb') as fichiers:
                os.write(mongo_keycert_handle, fichiers.read())

            os.environ["MG_MONGO_SSL_CERTFILE"] = mongo_keycert
        finally:
            os.close(mongo_keycert_handle)

        return mongo_keycert

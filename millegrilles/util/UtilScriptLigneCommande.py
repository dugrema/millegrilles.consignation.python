# Module avec des utilitaires pour la ligne de commande.

import argparse
import signal
import logging
import threading
import time
import sys

from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.SecuritePKI import GestionnaireEvenementsCertificat


class ModeleConfiguration:

    def __init__(self):
        self._logger = logging.getLogger('%s' % self.__class__.__name__)
        self._logger.setLevel(logging.INFO)
        self._contexte = ContexteRessourcesMilleGrilles()
        self.parser = None  # Parser de ligne de commande
        self.args = None  # Arguments de la ligne de commande

        self.__certificat_event_handler = GestionnaireEvenementsCertificat(self._contexte)
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

    def on_channel_open(self, channel):
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel
        self.__certificat_event_handler.initialiser()

    def on_channel_close(self, arg1, arg2, arg3):
        self.__channel = None
        self._logger.info("MQ Channel ferme")

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
        if self._contexte.message_dao is not None:
            self._contexte.message_dao.deconnecter()

        if self._contexte.document_dao is not None:
            self._contexte.document_dao.deconnecter()

    def set_logging_level(self):
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
        elif self.args.info:
            self._logger.setLevel(logging.INFO)
            logging.getLogger('millegrilles').setLevel(logging.INFO)

    def main(self):

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
            self._logger.info("Fin execution")

        except Exception as e:
            print("MAIN: Erreur fatale, voir log. Erreur %s" % str(e))
            self._logger.exception("MAIN: Erreur")
            self.print_help()
        finally:
            self.exit_gracefully()

        self._logger.info("Main terminee, exit.")

        if threading.active_count() > 1:
            ok_threads = ['MainThread', 'pymongo_kill_cursors_thread']
            for thread in threading.enumerate():
                if thread.name not in ok_threads:
                    self._logger.error("Thread ouverte apres demande de fermeture: %s" % thread.name)

            time.sleep(5)
            thread_encore_ouverte = False
            for thread in threading.enumerate():
                if thread.name not in ok_threads:
                    self._logger.error("Thread encore ouverte apres demande de fermeture: %s" % thread.name)
                    thread_encore_ouverte = True

            if thread_encore_ouverte:
                self._logger.error("Threads encore ouvertes, on force la sortie")
                sys.exit(2)

    @property
    def contexte(self):
        return self._contexte

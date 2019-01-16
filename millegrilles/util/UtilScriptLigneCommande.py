# Module avec des utilitaires pour la ligne de commande.

import argparse
import signal
import logging

from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.DocumentDAO import MongoDAO

logger = logging.getLogger(__name__)  # Define module logger


class ModeleConfiguration:

    def __init__(self):
        self._contexte = ContexteRessourcesMilleGrilles()
        self.parser = None  # Parser de ligne de commande
        self.args = None  # Arguments de la ligne de commande

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        # Gerer les signaux OS, permet de deconnecter les ressources au besoin
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

        self._contexte.initialiser(
            init_document=init_document,
            init_message=init_message,
            connecter=connecter
        )

    def configurer_parser(self):
        self.parser = argparse.ArgumentParser(description="Fonctionnalite MilleGrilles")

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

    def main(self):

        try:
            # Preparer logging
            logging.basicConfig(level=logging.WARNING)

            # Faire le parsing des arguments pour verifier s'il en manque
            self.configurer_parser()
            self.parse()

            self.initialiser()  # Initialiser toutes les

            self.connecter()  # Connecter les ressource (DAOs)

            self.executer()  # Executer le download et envoyer message

        except Exception as e:
            print("MAIN: Erreur fatale, voir log. Erreur %s" % str(e))
            logger.exception("MAIN: Erreur")
            self.print_help()
        finally:
            self.exit_gracefully()

    @property
    def contexte(self):
        return self._contexte

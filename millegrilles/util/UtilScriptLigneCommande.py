# Module avec des utilitaires pour la ligne de commande.

import argparse
import signal
import logging

from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles


class ModeleConfiguration:

    def __init__(self):
        self._logger = logging.getLogger('%s' % self.__class__.__name__)
        self._logger.setLevel(logging.INFO)
        self._contexte = ContexteRessourcesMilleGrilles()
        self.parser = None  # Parser de ligne de commande
        self.args = None  # Arguments de la ligne de commande

    def initialiser(self, init_document=True, init_message=True, connecter=False):
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
            logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.WARNING)
            self._logger.info("\n-----------\n\n-----------")
            self._logger.info("Demarrage de %s en cours\n-----------" % self.__class__.__name__)

            # Faire le parsing des arguments pour verifier s'il en manque
            self.configurer_parser()
            self.parse()

            self._logger.info("Initialisation")
            self.initialiser()  # Initialiser toutes les

            self._logger.info("Connexion des DAOs")
            self.connecter()  # Connecter les ressource (DAOs)

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

    @property
    def contexte(self):
        return self._contexte

# Module avec des utilitaires pour la ligne de commande.

import argparse
import signal
import logging

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.DocumentDAO import MongoDAO

logger = logging.getLogger(__name__)  # Define module logger


class ModeleConfiguration:

    def __init__(self):
        # Gerer les signaux OS, permet de deconnecter les ressources au besoin
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()

        self.parser = None  # Parser de ligne de commande
        self.args = None  # Arguments de la ligne de commande

        self.configurer_parser()

    def configurer_parser(self):
        self.parser = argparse.ArgumentParser(description="Fonctionnalite MilleGrilles")

    def print_help(self):
        self.parser.print_help()

    def exit_gracefully(self):
        pass

    def parse(self):
        self.args = self.parser.parse_args()

    def executer(self):
        raise NotImplemented("Cette methode doit etre redefinie")


class ModeleAvecMessageDAO(ModeleConfiguration):

    def __init__(self):
        super().__init__()

        # Ajouter le DAO
        self.message_dao = PikaDAO(self.configuration)

    def connecter(self):
        self.message_dao.connecter()

    def deconnecter(self):
        try:
            self.message_dao.deconnecter()
        except Exception as em:
            logging.warning("Erreur fermeture message dao: %s" % str(em))

    def exit_gracefully(self):
        self.deconnecter()

    def main(self):
        try:
            # Preparer logging
            logging.basicConfig(level=logging.WARNING)

            self.parse()  # Parsing de la ligne de commande

            if self.args.debug:
                # Active logging au niveau debug
                logging.getLogger(__name__).setLevel(logging.DEBUG)
                logging.getLogger("mgdomaines").setLevel(logging.DEBUG)

            self.connecter()  # Connecter les ressource (DAOs)
            self.executer()  # Executer le download et envoyer message

        except Exception as e:
            print("MAIN: Erreur fatale, voir log. Erreur %s" % str(e))
            logger.exception("MAIN: Erreur")
            self.print_help()
        finally:
            self.deconnecter()  # Deconnecter les ressources (DAOs)


# Classe qui inclue la configuration pour les messages et les documents
class ModeleAvecDocumentDAO(ModeleConfiguration):

    def __init__(self):
        super().__init__()

        # Ajouter le DAO
        self.document_dao = MongoDAO(self.configuration)

    def connecter(self):
        self.document_dao.connecter()

    def deconnecter(self):
        try:
            self.document_dao.deconnecter()
        except Exception as ed:
            logging.warning("Erreur fermeture document dao: %s" % str(ed))

    def exit_gracefully(self):
        self.deconnecter()

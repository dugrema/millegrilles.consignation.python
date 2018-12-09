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
        self.configuration = None
        self.parser = None  # Parser de ligne de commande
        self.args = None  # Arguments de la ligne de commande

    def initialiser(self):
        if self.configuration is None:
            # Gerer les signaux OS, permet de deconnecter les ressources au besoin
            signal.signal(signal.SIGINT, self.exit_gracefully)
            signal.signal(signal.SIGTERM, self.exit_gracefully)

            self.configuration = TransactionConfiguration()
            self.configuration.loadEnvironment()

            self.configurer_parser()

    def configurer_parser(self):
        self.parser = argparse.ArgumentParser(description="Fonctionnalite MilleGrilles")

    def print_help(self):
        self.parser.print_help()

    def exit_gracefully(self, signal=None, frame=None):
        self.deconnecter()

    def parse(self):
        self.args = self.parser.parse_args()

    def executer(self):
        raise NotImplemented("Cette methode doit etre redefinie")

    def connecter(self):
        pass

    def deconnecter(self):
        pass

    def main(self):

        try:
            # Preparer logging
            logging.basicConfig(level=logging.WARNING)

            self.parse()  # Parsing de la ligne de commande

            self.connecter()  # Connecter les ressource (DAOs)

            self.executer()  # Executer le download et envoyer message

        except Exception as e:
            print("MAIN: Erreur fatale, voir log. Erreur %s" % str(e))
            logger.exception("MAIN: Erreur")
            self.print_help()
        finally:
            self.exit_gracefully()


class ModeleAvecMessageDAO(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.message_dao = None

    def initialiser(self):
        super().initialiser()
        self.message_dao = PikaDAO(self.configuration)

    def connecter(self):
        self.message_dao.connecter()

    def deconnecter(self):
        try:
            self.message_dao.deconnecter()
        except Exception as em:
            logging.warning("Erreur fermeture message dao: %s" % str(em))


# Classe qui inclue la configuration pour les messages et les documents
class ModeleAvecDocumentDAO(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.document_dao = None

    def initialiser(self):
        super().initialiser()
        self.document_dao = MongoDAO(self.configuration)

    def connecter(self):
        self.document_dao.connecter()

    def deconnecter(self):
        try:
            self.document_dao.deconnecter()
        except Exception as ed:
            logging.warning("Erreur fermeture document dao: %s" % str(ed))


# Classe qui implemente a la fois les DAO de messages et documents
class ModeleAvecDocumentMessageDAO(ModeleAvecMessageDAO, ModeleAvecDocumentDAO):

    def __init__(self):
        ModeleAvecMessageDAO.__init__(self)
        ModeleAvecDocumentDAO.__init__(self)

    def initialiser(self):
        ModeleAvecMessageDAO.initialiser(self)
        ModeleAvecDocumentDAO.initialiser(self)

    def connecter(self):
        ModeleAvecMessageDAO.connecter(self)
        ModeleAvecDocumentDAO.connecter(self)

    def deconnecter(self):
        ModeleAvecMessageDAO.deconnecter(self)
        ModeleAvecDocumentDAO.deconnecter(self)

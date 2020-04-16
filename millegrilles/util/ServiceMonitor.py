import argparse
import signal
import logging
import sys
import docker

from threading import Event, Thread
from docker.errors import APIError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.util import UtilScriptLigneCommande
from millegrilles.SecuritePKI import GestionnaireEvenementsCertificat

SERVICEMONITOR_LOGGING_FORMAT = '%(threadName)s:%(levelname)s:%(message)s'


class ServiceMonitor:
    """
    Service deploye dans un swarm docker en mode global qui s'occupe du deploiement des autres modules de la
    MilleGrille et du renouvellement des certificats. S'occupe de configurer les comptes RabbitMQ et MongoDB.

    Supporte aussi les MilleGrilles hebergees par l'hote.
    """

    def __init__(self):
        self.__logger = logging.getLogger('%s' % self.__class__.__name__)

        self.__securite = None              # Niveau de securite de la swarm docker
        self.__args = None                  # Arguments de la ligne de commande
        self.__connexion_middleware = None  # Connexion a MQ, MongoDB
        self.__docker = None                # Client docker

        self.__fermeture_event = Event()

        # Gerer les signaux OS, permet de deconnecter les ressources au besoin
        signal.signal(signal.SIGINT, self.fermer)
        signal.signal(signal.SIGTERM, self.fermer)

    def parse(self):
        parser = argparse.ArgumentParser(description="Service Monitor de MilleGrilles")

        parser.add_argument(
            '--debug', action="store_true", required=False,
            help="Active le debugging (tres verbose)"
        )

        parser.add_argument(
            '--info', action="store_true", required=False,
            help="Afficher davantage de messages (verbose)"
        )

        parser.add_argument(
            '--securite', type=str, required=False, default='protege',
            choices=['prive', 'protege', 'secure'],
            help="Niveau de securite du noeud. Defaut = protege"
        )

        parser.add_argument(
            '--docker', type=str, required=False, default='/run/docker.sock',
            help="Path du pipe docker"
        )

        parser.add_argument(
            '--pipe', type=str, required=False, default='/run/millegrille.sock',
            help="Path du pipe de controle du ServiceMonitor"
        )

        parser.add_argument(
            '--config', type=str, required=False, default='/etc/opt/millegrilles',
            help="Path de la configuration de l'hote MilleGrilles"
        )

        parser.add_argument(
            '--data', type=str, required=False, default='/var/opt/millegrilles',
            help="Path du repertoire data de toutes les MilleGrilles"
        )

        self.__args = parser.parse_args()

        # Appliquer args
        if self.__args.debug:
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
            self.__logger.setLevel(logging.DEBUG)
        elif self.__args.info:
            logging.getLogger('millegrilles').setLevel(logging.INFO)

        self.__securite = self.__args.securite

        self.__logger.info("Arguments: %s", self.__args)

    def fermer(self, signum=None, frame=None):
        if signum:
            self.__logger.warning("Fermeture ServiceMonitor, signum=%d", signum)
        if not self.__fermeture_event.is_set():
            self.__fermeture_event.set()

    def verifier_etat_courant(self):
        """
        :return: Etat courant detecte sur le systeme.
        """
        pass

    def generer_certificats_CA_initiaux(self):
        """
        Generer un certificat de millegrille, intermediaire et leurs cles/mots de passe.
        Insere les fichiers dans docker config/secret.
        :return:
        """
        pass

    def connecter_middleware(self):
        """
        Genere un contexte et se connecte a MQ et MongoDB.
        Lance une thread distincte pour s'occuper des messages.
        :return:
        """
        pass

    def __connecter_docker(self):
        self.__docker = docker.DockerClient('unix://' + self.__args.docker)

        self.__logger.debug("--------------")
        self.__logger.debug("Docker configs")
        self.__logger.debug("--------------")
        for config in self.__docker.configs.list():
            self.__logger.debug("  %s", str(config.name))

        self.__logger.debug("--------------")
        self.__logger.debug("Docker secrets")
        self.__logger.debug("--------------")
        for secret in self.__docker.secrets.list():
            self.__logger.debug("  %s", str(secret.name))

        self.__logger.debug("--------------")
        self.__logger.debug("Docker services")
        self.__logger.debug("--------------")
        for service in self.__docker.services.list():
            self.__logger.debug("  %s", str(service.name))

        self.__logger.debug("--------------")

    def run(self):
        self.__logger.info("Demarrage du ServiceMonitor")
        self.parse()
        self.__connecter_docker()

        try:
            self.__logger.debug("Cycle entretien ServiceMonitor")

            self.__logger.debug("Fin cycle entretien ServiceMonitor")
        except Exception:
            self.__logger.exception("Erreur generique")
        finally:
            self.__fermeture_event.wait(30)

        self.__logger.info("Fermeture du ServiceMonitor")


class ConnexionMiddleware:
    """
    Connexion au middleware de la MilleGrille en service.
    """

    def __init__(self):
        self.__contexte = None
        self.__thread = None
        self.__channel = None

        self.__fermeture_event = Event()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__certificat_event_handler = GestionnaireEvenementsCertificat(self.__contexte)

    def start(self):
        self.__logger.info("Demarrage ConnexionMiddleware")
        # Generer contexte

        # Connecter

        # Demarrer thread
        self.__thread = Thread(target=self.run, name="mw")
        self.__thread.start()

    def stop(self):
        self.__fermeture_event.set()

        # try:
        #     self.__contexte.deconnecter()
        # except Exception:
        #     pass

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        self.__contexte.initialiser(
            init_document=init_document,
            init_message=init_message,
            connecter=connecter
        )

        if init_message:
            self.__contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel
        self.__certificat_event_handler.initialiser()

    def on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.__logger.warning("MQ Channel ferme")
        if not self.__fermeture_event.is_set():
            try:
                self.__contexte.message_dao.enter_error_state()
            except Exception:
                # Erreur d'activation du error state, la connexion ne peut pas etre reactivee
                self.__logger.exception("Erreur fermeture channel")
                self.__fermeture_event.set()  # S'assurer que la fermeture est en cours

    def __on_return(self, channel, method, properties, body):
        pass

    def run(self):
        self.__logger.info("Thread middleware demarree")

        self.__logger.info("Fin thread middleware")


# Section main
if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format=SERVICEMONITOR_LOGGING_FORMAT)
    logging.getLogger(ServiceMonitor.__name__).setLevel(logging.INFO)

    ServiceMonitor().run()

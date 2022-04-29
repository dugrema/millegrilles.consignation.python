import argparse
import docker
import logging
import sys

from base64 import b64decode
from typing import cast

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.SecuritePKI import CertificatExpire
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.ServiceMonitorInstalleur import ServiceMonitorInstalleur
from millegrilles.monitor.ServiceMonitorExpire import ServiceMonitorExpire
from millegrilles.monitor.ServiceMonitorPrive import ServiceMonitorPrive
from millegrilles.monitor.ServiceMonitorProtege import ServiceMonitorProtege
from millegrilles.monitor.ServiceMonitorPublic import ServiceMonitorPublic


class InitialiserServiceMonitor:

    def __init__(self):
        self.__docker: docker.DockerClient = cast(docker.DockerClient, None)  # Client docker
        self.__args = None
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._configuration_json = None

    def __parse(self):
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
            '--dev', action="store_true", required=False,
            help="Active des options de developpement (insecure)"
        )

        parser.add_argument(
            '--secrets', type=str, required=False, default="/run/secrets",
            help="Repertoire de secrets"
        )

        parser.add_argument(
            '--configs', type=str, required=False, default="/etc/opt/millegrille",
            help="Repertoire de configuration"
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
            '--pipe', type=str, required=False, default=MonitorConstantes.PATH_FIFO,
            help="Path du pipe de controle du ServiceMonitor"
        )

        parser.add_argument(
            '--config', type=str, required=False, default='/etc/opt/millegrilles/servicemonitor.json',
            help="Path du fichier de configuration de l'hote MilleGrilles"
        )

        parser.add_argument(
            '--data', type=str, required=False, default='/var/opt/millegrilles',
            help="Path du repertoire data de toutes les MilleGrilles"
        )

        parser.add_argument(
            '--webroot', type=str, required=False, default='/var/opt/millegrilles/installation',
            help="Path du webroot de l'installeur"
        )

        self.__args = parser.parse_args()

        # Appliquer args
        if self.__args.debug:
            logging.getLogger('__main__').setLevel(logging.DEBUG)
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
            self.__logger.setLevel(logging.DEBUG)
        elif self.__args.info:
            logging.getLogger('__main__').setLevel(logging.INFO)
            logging.getLogger('millegrilles').setLevel(logging.INFO)

        self.__logger.info("Arguments: %s", self.__args)

    def __connecter_docker(self):
        self.__docker = docker.DockerClient('unix://' + self.__args.docker)
        # self.__logger.debug("Docker info: %s", str(self.__docker.info()))

        self.__nodename = self.__docker.info()['Name']
        self.__logger.debug("Docker node name: %s", self.__nodename)

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

    def detecter_type_noeud(self):
        self.__parse()
        self.__connecter_docker()

        try:
            # Charger noeud_id et idmg - si absents, on tombe automatiquent en mode installation
            config_noeud_id = self.__docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_NOEUD_ID)
            noeud_id = b64decode(config_noeud_id.attrs['Spec']['Data']).decode('utf-8').strip()
            config_idmg = self.__docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_IDMG)
            idmg = b64decode(config_idmg.attrs['Spec']['Data']).decode('utf-8').strip()

            # Charger niveau de securite - peut etre configure manuellement (installeur web)
            config_securite = self.__docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_SECURITE)
            securite = b64decode(config_securite.attrs['Spec']['Data']).decode('utf-8').strip()
            self.__logger.debug("Niveau de securite millegrille : %s" % securite)

            # Verifier si on a le cert de monitor - indique que noeud est configure et completement installe
            # Lance une exception si aucune configuration ne commence par pki.monitor.cert
            # monitor_cert = self.__docker.configs.list(filters={'name': 'pki.monitor.cert'})[0]

            if securite == Constantes.SECURITE_PUBLIC and noeud_id is not None:
                self.__logger.info("Noeud public")
                service_monitor_classe = ServiceMonitorPublic
            elif securite == Constantes.SECURITE_PRIVE and noeud_id is not None:
                self.__logger.info("Noeud prive")
                service_monitor_classe = ServiceMonitorPrive
            elif securite == Constantes.SECURITE_PROTEGE:
                service_monitor_classe = ServiceMonitorProtege
            else:
                raise ValueError("Noeud de type non reconnu")
        except (docker.errors.NotFound, IndexError):
            self.__logger.info("Config millegrille.configuration n'existe pas, le noeud est demarre en mode d'installation")
            service_monitor_classe = ServiceMonitorInstalleur

        return service_monitor_classe

    def demarrer(self):
        class_noeud = self.detecter_type_noeud()
        self.__logger.info("Chargement d'un monitor type %s", class_noeud.__name__)

        service_monitor = class_noeud(self.__args, self.__docker, self._configuration_json)
        try:
            service_monitor.run()
        except CertificatExpire:
            # Lancer en mode installation
            self.__logger.exception("Certificat expire, on lance en mode installeur")
            installeur = ServiceMonitorExpire(self.__args, self.__docker, self._configuration_json)
            installeur.run()


# Section main
if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format=MonitorConstantes.SERVICEMONITOR_LOGGING_FORMAT)
    logging.getLogger(InitialiserServiceMonitor.__name__).setLevel(logging.INFO)

    # ServiceMonitor().run()
    InitialiserServiceMonitor().demarrer()

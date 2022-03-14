import json
import logging

import docker

from millegrilles import Constantes
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.MonitorConstantes import CommandeMonitor
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker
from millegrilles.monitor.MonitorNetworking import GestionnaireWeb
from millegrilles.monitor.ServiceMonitorSatellite import ServiceMonitorSatellite
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat


class ServiceMonitorPrive(ServiceMonitorSatellite):
    """
    ServiceMonitor pour noeud prive
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)

    def configurer_millegrille(self):
        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_PRIVE_PUBLIC.copy(),
            self,
            configuration_services=MonitorConstantes.DICT_MODULES_PRIVES,
            insecure=self._args.dev,
            secrets=self._args.secrets
        )

        self._gestionnaire_docker.start_events()
        self._gestionnaire_docker.add_event_listener(self)

        # Initialiser gestionnaire web
        self._gestionnaire_web = GestionnaireWeb(self, mode_dev=self._args.dev)

    def initialiser_noeud(self, commande: CommandeMonitor):
        if self.__logger.isEnabledFor(logging.DEBUG):
            try:
                self.__logger.debug("Commande initialiser noeud : %s", json.dumps(commande.contenu, indent=2))
            except Exception:
                self.__logger.debug("Commande initialiser noeud : %s", commande.contenu)

        params = commande.contenu
        self._renouveller_certificat_monitor(commande)

    def ajouter_compte(self, certificat: str):
        raise Exception("Ajouter compte PEM (**non implemente pour prive**): %s" % certificat)

    @property
    def securite(self):
        return Constantes.SECURITE_PRIVE

    @property
    def role(self):
        return ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE

    @property
    def nom_service_nginx(self):
        return 'nginx_public'
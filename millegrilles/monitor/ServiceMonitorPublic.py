import json
import logging

import docker

from millegrilles import Constantes
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.MonitorConstantes import CommandeMonitor, DICT_MODULES_PUBLICS
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker
from millegrilles.monitor.MonitorNetworking import GestionnaireWeb
from millegrilles.monitor.ServiceMonitorSatellite import ServiceMonitorSatellite
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat


class ServiceMonitorPublic(ServiceMonitorSatellite):
    """
    ServiceMonitor pour noeud public
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)

    def configurer_millegrille(self):
        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_PRIVE_PUBLIC.copy(),
            self,
            configuration_services=DICT_MODULES_PUBLICS,
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
        try:
            hostname = params['hostname']
            self._conserver_config_acme(hostname)
        except KeyError:
            self.__logger.warning("Hostname absent de la commande d'installation")

        self._renouveller_certificat_monitor(commande)

    @property
    def securite(self):
        return Constantes.SECURITE_PUBLIC

    @property
    def role(self):
        return ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC

    @property
    def nom_service_nginx(self):
        return 'nginx'

    def _get_dict_modules(self) -> dict:
        return DICT_MODULES_PUBLICS


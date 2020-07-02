# Gestionnaire d'applications privees
import logging
import docker
import json

from threading import Event
from typing import cast
from base64 import b64decode

from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.monitor.MonitorCommandes import GestionnaireCommandes
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker, GestionnaireImagesDocker
from millegrilles.monitor.MonitorConstantes import CommandeMonitor


class GestionnaireApplications:
    """
    Installe et configure une application tierce
    """

    def __init__(self,
                 service_monitor,
                 gestionnaire_modules_docker: GestionnaireModulesDocker):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__service_monitor = service_monitor
        self.__gestionnaire_modules_docker = gestionnaire_modules_docker

        self.__gestionnaire_images_applications = GestionnaireImagesApplications(service_monitor.idmg, service_monitor.docker)

    def installer_application(self, commande: CommandeMonitor):
        self.__logger.info("Installation application %s", str(commande))

        nom_image_docker = commande.contenu['nom_application']
        self.__logger.info("Telecharger image docker %s" % nom_image_docker)
        image = self.__gestionnaire_images_applications.telecharger_image_docker(nom_image_docker)

        self.__logger.debug("Image docker %s telechargee" % nom_image_docker)


    def telecharger_images(self, nom_images: list):
        pass

    def installer_dependances(self, dependances: list):
        pass

    def executer_scripts(self, container, script):
        pass


class GestionnaireImagesApplications(GestionnaireImagesDocker):

    def __init__(self, idmg: str, docker_client: docker.DockerClient):
        super().__init__(idmg, docker_client)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._versions_images: dict = cast(dict, None)

    def charger_versions(self):
        with open('/home/mathieu/PycharmProjects/millegrilles.consignation.python/test/json/postgres.sharedapp.json', 'r') as fichier:
            self._versions_images = json.load(fichier)

# Gestionnaire d'applications privees
import logging
import docker
import json
import secrets

from threading import Event
from typing import cast
from base64 import b64encode, b64decode
from os import path, remove

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

        # Ecouter evenements dokcer
        self.__gestionnaire_modules_docker.add_event_listener(self)

        self.__wait_container_event = Event()
        self.__wait_start_service_name = None
        self.__wait_start_service_container_id = None

    def event(self, event):
        self.__logger.debug("Event docker APPS : %s", str(event))

        if self.__wait_start_service_name:
            event_json = json.loads(event.decode('utf-8'))

            # Verifier si le container correspond au service
            if event_json.get('Type') == 'container' and event_json.get('status') == 'start' and event_json.get('Action') == 'start':
                actor = event_json.get('Actor')
                if actor:
                    attributes = actor.get('Attributes')
                    if attributes:
                        service_name = attributes.get('com.docker.swarm.service.name')
                        if service_name == self.__wait_start_service_name:
                            self.__logger.debug("Service %s demarre" % service_name)
                            self.__wait_start_service_container_id = event_json['id']
                            self.__wait_container_event.set()

    def installer_application(self, commande: CommandeMonitor):
        self.__logger.info("Installation application %s", str(commande))

        nom_image_docker = commande.contenu['nom_application']
        configuration_docker = commande.contenu['configuration']
        tar_scripts = commande.contenu.get('scripts_tarfile')
        self.preparer_installation(nom_image_docker, configuration_docker, tar_scripts)

    def supprimer_application(self, commande: CommandeMonitor):
        self.__logger.info("Supprimer application %s", str(commande))

        nom_image_docker = commande.contenu['nom_application']
        configuration_docker = commande.contenu['configuration']
        self.effectuer_desinstallation(nom_image_docker, configuration_docker)

    def preparer_installation(self, nom_image_docker, configuration_docker, tar_scripts=None):
        gestionnaire_images_applications = GestionnaireImagesApplications(
            self.__service_monitor.idmg, self.__service_monitor.docker)
        gestionnaire_images_applications.set_configuration(configuration_docker)

        config_name = self.__service_monitor.idmg_tronque + '.app.' + nom_image_docker

        self.__gestionnaire_modules_docker.sauvegarder_config(config_name, configuration_docker)

        # Verifier le type de configuration : image ou dependance avec config

        # Installer toutes les dependances de l'application en ordre
        for config_image in configuration_docker['dependances']:
            if config_image.get('dependances'):
                # Sous dependances presentes, c'est une sous-config
                nom_image_docker = config_image['nom']
                self.preparer_installation(nom_image_docker, config_image)
            elif config_image.get('image'):
                # C'est une image, on l'installe
                self.installer_dependance(gestionnaire_images_applications, config_image, tar_scripts)

        nginx_config = configuration_docker.get('nginx')
        if nginx_config:
            conf = nginx_config['conf']

            # Remplacer les variables de conf
            app_domain = 'redmine.mg-dev4.maple.maceroc.com'
            server_domain = 'mg-dev4.maple.maceroc.com'

            conf = conf.replace("${APP_DOMAIN}", app_domain)
            conf = conf.replace("${SERVER_DOMAIN}", server_domain)

            if nginx_config.get('params'):
                for key, value in nginx_config['params'].items():
                    conf = conf.replace('${%s}' % key, value)

            # Injecter le fichier dans le repertoire de nginx
            path_nginx = '/var/opt/millegrilles/%s/mounts/nginx/conf.d/modules' % self.__service_monitor.idmg
            nom_config = nginx_config['server_file']
            with open(path.join(path_nginx, nom_config), 'w') as fichier:
                fichier.write(conf)

            # Redemarrer nginx
            nom_service_nginx = 'nginx'
            self.__gestionnaire_modules_docker.force_update_service(nom_service_nginx)

    def installer_dependance(self, gestionnaire_images_applications, config_image, tar_scripts=None):
        nom_image_docker = config_image['image']
        config_name = 'docker.cfg.' + nom_image_docker
        config_elem = config_image['config']
        self.__gestionnaire_modules_docker.sauvegarder_config(config_name, config_elem)

        # Generer valeurs au besoin
        valeurs_a_generer = config_image.get('generer')
        mots_de_passe = dict()
        if valeurs_a_generer:
            liste_motsdepasse = valeurs_a_generer.get('motsdepasse')
            for motdepasse_config in liste_motsdepasse:
                label_motdepasse = self.__service_monitor.idmg_tronque + '.' + motdepasse_config['name']

                # Verifier si le mot de passe existe deja
                try:
                    secret_passwd = self.__gestionnaire_modules_docker.trouver_secret(motdepasse_config['name'])
                except AttributeError:
                    # Generer le mot de passe
                    motdepasse = b64encode(secrets.token_bytes(16))
                    # Conserver mot de passe en memoire pour generer script, au besoin
                    mots_de_passe[label_motdepasse] = motdepasse.decode('utf-8')
                    self.__gestionnaire_modules_docker.sauvegarder_secret(label_motdepasse, motdepasse, ajouter_date=True)

        # Preparer le demarrage du service, intercepter le demarrage du container
        service_name = self.__service_monitor.idmg_tronque + '_' + config_elem['name']
        self.__wait_start_service_name = service_name
        self.__wait_container_event.clear()

        self.__gestionnaire_modules_docker.demarrer_service(nom_image_docker,
                                                            config=config_elem,
                                                            images=gestionnaire_images_applications)

        self.__wait_container_event.wait(60)
        self.__wait_start_service_name = None  # Reset ecoute de l'evenement

        if self.__wait_container_event.is_set():
            self.__logger.info("Executer script d'installation du container id : %s" % self.__wait_start_service_container_id)
            self.__wait_container_event.clear()

            # Preparer les scripts dans un fichier .tar temporaire
            # path_script = '/home/mathieu/PycharmProjects/millegrilles.consignation.python/test/scripts.apps.tar'
            # commande_script = '/tmp/apps/script.redmine.postgres.installation.sh'
            if config_image.get('installation'):
                self.__gestionnaire_modules_docker.executer_scripts(
                    self.__wait_start_service_container_id, config_image['installation'], tar_scripts)

        else:
            self.__logger.error("Erreur demarrage service (timeout) : %s" % nom_image_docker)
            raise Exception("Image non installee : " + nom_image_docker)

    def effectuer_desinstallation(self, nom_image_docker, configuration_docker):

        # Nettoyer fichiers de configurations
        nginx_config = configuration_docker.get('nginx')
        if nginx_config:
            # Injecter le fichier dans le repertoire de nginx
            try:
                path_nginx = '/var/opt/millegrilles/%s/mounts/nginx/conf.d/modules' % self.__service_monitor.idmg
                nom_config = nginx_config['server_file']
                remove(path.join(path_nginx, nom_config))

                # Redemarrer nginx
                nom_service_nginx = 'nginx'
                self.__gestionnaire_modules_docker.force_update_service(nom_service_nginx)
            except FileNotFoundError:
                pass  # OK

        # Supprimer les dependances (a l'envers, recursif)
        liste_config = list(configuration_docker['dependances'])
        liste_config.reverse()
        for config_image in liste_config:
            try:
                if config_image.get('dependances'):
                    # Sous dependances presentes, c'est une sous-config. Appel recursif.
                    nom_image_docker = config_image['nom']
                    self.effectuer_desinstallation(nom_image_docker, config_image)
                elif config_image.get('image'):
                    # C'est une image, on l'installe
                    nom_service = config_image['config']['name']
                    self.__gestionnaire_modules_docker.supprimer_service(nom_service)

                    config_name = self.__service_monitor.idmg_tronque + '.app.' + nom_image_docker
                    self.__gestionnaire_modules_docker.supprimer_config(config_name)

            except IndexError:
                pass  # OK, service absent


class GestionnaireImagesApplications(GestionnaireImagesDocker):

    def __init__(self, idmg: str, docker_client: docker.DockerClient):
        super().__init__(idmg, docker_client)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._versions_images: dict = cast(dict, None)

    def set_configuration(self, configuration):
        self._versions_images = configuration

    def charger_versions(self):
        pass

    @property
    def config(self):
        return self._versions_images

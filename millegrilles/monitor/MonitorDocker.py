import json
import logging
import os
from base64 import b64decode
from threading import Event, Thread
from typing import cast
import datetime

import docker
from docker.errors import APIError
from docker.types import SecretReference, NetworkAttachmentConfig, Resources, RestartPolicy, ServiceMode, \
    ConfigReference, EndpointSpec

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.MonitorConstantes import ImageNonTrouvee


class GestionnaireModulesDocker:

    def __init__(self, idmg: str, docker_client: docker.DockerClient, fermeture_event: Event, modules_requis: list):
        self.__idmg = idmg
        self.__docker = docker_client
        self.configuration_json = None
        self.__fermeture_event = fermeture_event
        self.__thread_events: Thread = cast(Thread, None)
        self.__event_stream = None
        self.__modules_requis = modules_requis
        self.__hebergement_actif = False

        self.__mappings = {
            'IDMG': self.__idmg,
            'IDMGLOWER': self.__idmg.lower(),
            'IDMGTRUNCLOWER': self.idmg_tronque,
            'MONGO_INITDB_ROOT_USERNAME': 'admin',
            'MOUNTS': '/var/opt/millegrilles/%s/mounts' % self.__idmg,
        }

        self.__event_listeners = list()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def start_events(self):
        self.__thread_events = Thread(target=self.ecouter_events, name='events', daemon=True)
        self.__thread_events.start()

    def fermer(self):
        try:
            self.__event_stream.close()
        except Exception:
            pass

    def add_event_listener(self, listener):
        self.__event_listeners.append(listener)

    def remove_event_listener(self, listener):
        self.__event_listeners = [l for l in self.__event_listeners if l is not listener]

    def ecouter_events(self):
        self.__logger.info("Debut ecouter events docker")
        self.__event_stream = self.__docker.events()
        for event in self.__event_stream:
            self.__logger.debug("Event : %s", str(event))
            to_remove = list()
            for listener in self.__event_listeners:
                try:
                    listener.event(event)
                except Exception:
                    self.__logger.exception("Erreur event listener")
                    to_remove.append(listener)

            for listener in to_remove:
                self.remove_event_listener(listener)

            if self.__fermeture_event.is_set():
                break
        self.__logger.info("Fin ecouter events docker")

    def initialiser_millegrille(self):
        # Creer reseau pour cette millegrille
        network_name = 'mg_' + self.__idmg + '_net'
        labels = {'millegrille': self.__idmg}
        self.__docker.networks.create(name=network_name, labels=labels, scope="swarm", driver="overlay")

    def configurer_monitor(self):
        """
        Ajoute les element de configuration generes (e.g. secrets).
        :return:
        """
        noms_secrets = {
            'passwd.mongo': ConstantesServiceMonitor.FICHIER_MONGO_MOTDEPASSE,
            'passwd.mq': ConstantesServiceMonitor.FICHIER_MQ_MOTDEPASSE,
            'passwd.mongoxpweb': ConstantesServiceMonitor.FICHIER_MONGOXPWEB_MOTDEPASSE,
            ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_KEY: ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_KEY + '.pem',
            ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_PASSWD: ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_PASSWD + '.pem',
            ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_KEY: ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_KEY + '.pem',
        }

        liste_secrets = list()
        for nom_secret, nom_fichier in noms_secrets.items():
            self.__logger.debug("Preparer secret %s pour service monitor", nom_secret)
            secret_reference = self.trouver_secret(nom_secret)
            secret_reference['filename'] = nom_fichier
            secret_reference['uid'] = 0
            secret_reference['gid'] = 0
            secret_reference['mode'] = 0o444

            del secret_reference['date']

            liste_secrets.append(SecretReference(**secret_reference))

        network = NetworkAttachmentConfig(target='mg_%s_net' % self.__idmg)

        # Ajouter secrets au service monitor
        filtre = {'name': 'service_monitor'}
        services_list = self.__docker.services.list(filters=filtre)
        service_monitor = services_list[0]
        service_monitor.update(secrets=liste_secrets, networks=[network])

    def entretien_services(self):
        """
        Verifie si les services sont actifs, les demarre au besoin.
        :return:
        """
        filtre = {'name': self.idmg_tronque + '_'}
        liste_services = self.__docker.services.list(filters=filtre)
        dict_services = dict()
        for service in liste_services:
            # Enlever prefix avec IDMG
            service_name = '_'.join(service.name.split('_')[1:])
            dict_services[service_name] = service

        for service_name in self.__modules_requis:
            params = MonitorConstantes.DICT_MODULES[service_name]
            service = dict_services.get(service_name)
            if not service:
                try:
                    self.demarrer_service(service_name, **params)
                except IndexError:
                    self.__logger.error("Configuration service docker.cfg.%s introuvable" % service_name)
                break  # On demarre un seul service a la fois, on attend qu'il soit pret
            else:
                # Verifier etat service
                self.verifier_etat_service(service)

    def demarrer_service(self, service_name: str, **kwargs):
        self.__logger.info("Demarrage service %s", service_name)

        configuration_service = kwargs.get('config')
        if not configuration_service:
            configuration_service = MonitorConstantes.DICT_MODULES.get(service_name)

        gestionnaire_images = kwargs.get('images')
        if not gestionnaire_images:
            gestionnaire_images = GestionnaireImagesServices(self.__idmg, self.__docker)

        if configuration_service:
            # S'assurer que le certificat existe et est a date
            pass

        nom_image_docker = kwargs.get('nom') or service_name

        try:
            image = gestionnaire_images.telecharger_image_docker(nom_image_docker)

            # Prendre un tag au hasard
            image_tag = image.tags[0]

            configuration = self.__formatter_configuration_service(service_name)

            constraints = configuration.get('constraints')
            if constraints:
                self.__add_node_labels(constraints)

            self.__docker.services.create(image_tag, **configuration)
        except KeyError as ke:
            self.__logger.error("Erreur chargement image %s, key error sur %s" % (nom_image_docker, str(ke)))
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail erreur chargement image")
        except AttributeError as ae:
            self.__logger.error("Erreur configuration service %s : %s" % (service_name, str(ae)))
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail erreur configuration service " + service_name)
        except APIError as apie:
            if apie.status_code == 409:
                self.__logger.info("Service %s deja demarre" % service_name)
            else:
                self.__logger.exception("Erreur demarrage service %s" % service_name)

    def supprimer_service(self, service_name: str):
        filter = {'name': self.idmg_tronque + '_' + service_name}
        service_list = self.__docker.services.list(filters=filter)
        service_list[0].remove()

    def activer_hebergement(self):
        """
        Active les modules d'hebergement (si pas deja fait).
        :return:
        """
        if not self.__hebergement_actif:
            # S'assurer que le repertoire d'hebergement de la MilleGrille est cree
            path_hebergement = os.path.join(Constantes.DEFAUT_VAR_MILLEGRILLES, self.__idmg, 'mounts/hebergement')
            try:
                os.mkdir(path_hebergement, mode=0o770)
            except FileExistsError:
                self.__logger.debug("Repertoire %s existe, ok" % path_hebergement)

            # Ajouter modules requis
            modules_requis = set(self.__modules_requis)
            modules_requis.update(MonitorConstantes.MODULES_HEBERGEMENT)
            self.__modules_requis = list(modules_requis)

            for service_name in MonitorConstantes.MODULES_HEBERGEMENT:
                module_config = MonitorConstantes.DICT_MODULES[service_name]
                self.demarrer_service(service_name, **module_config)

            self.__hebergement_actif = True

    def desactiver_hebergement(self):
        if self.__hebergement_actif:
            modules_requis = set(self.__modules_requis)
            modules_requis.difference_update(MonitorConstantes.MODULES_HEBERGEMENT)
            self.__modules_requis = list(modules_requis)

            for service_name in MonitorConstantes.MODULES_HEBERGEMENT:
                try:
                    self.supprimer_service(service_name)
                except IndexError:
                    self.__logger.warning("Erreur retrait service %s" % service_name)
                self.__hebergement_actif = False

    def force_update_service(self, service_name):
        filter = {'name': self.idmg_tronque + '_' + service_name}
        service_list = self.__docker.services.list(filters=filter)
        service_list[0].force_update()

    def verifier_etat_service(self, service):
        update_state = None
        update_status = service.attrs.get('UpdateStatus')
        if update_status is not None:
            update_state = update_status['State']

        # Compter le nombre de taches actives
        running = list()

        for task in service.tasks():
            status = task['Status']
            state = status['State']
            desired_state = task['DesiredState']
            if state == 'running' or desired_state == 'running' or update_state == 'updating':
                # Le service est actif
                running.append(running)

        if len(running) == 0:
            # Redemarrer
            self.__logger.info("Redemarrer service %s", service.name)
            service.force_update()

    def charger_config(self, config_name):
        filtre = {'name': config_name}
        configs = self.__docker.configs.list(filters=filtre)
        return b64decode(configs[0].attrs['Spec']['Data'])

    def sauvegarder_secret(self, secret_name: str, data: bytes, ajouter_date=False):
        if ajouter_date:
            date_courante = datetime.datetime.utcnow().strftime(MonitorConstantes.DOCKER_LABEL_TIME)
            secret_name = secret_name + '.' + date_courante
        self.__docker.secrets.create(name=secret_name, data=data, labels={'idmg': self.__idmg})

    def sauvegarder_config(self, config_name, data: dict):
        filtre = {'name': config_name}
        configs = self.__docker.configs
        config_existante = configs.list(filters=filtre)
        if len(config_existante) == 1:
            config_existante[0].remove()
        data_string = json.dumps(data).encode('utf-8')
        configs.create(name=config_name, data=data_string)

    def charger_config_recente(self, config_name):
        return self.__trouver_config(config_name)

    def __trouver_config(self, config_name):
        return MonitorConstantes.trouver_config(config_name, self.__idmg[0:12], self.__docker)

    def trouver_secret(self, secret_name):
        secret_names = secret_name.split(';')
        secrets = None
        for secret_name_val in secret_names:
            filtre = {'name': self.idmg_tronque + '.' + secret_name_val}
            secrets = self.__docker.secrets.list(filters=filtre)
            if len(secrets) > 0:
                break

        # Trouver la configuration la plus recente (par date). La meme date va etre utilise pour un secret, au besoin
        date_secret: int = cast(int, None)
        secret_retenue = None
        for secret in secrets:
            nom_secret = secret.name
            split_secret = nom_secret.split('.')
            date_secret_str = split_secret[-1]
            date_secret_int = int(date_secret_str)
            if not date_secret or date_secret_int > date_secret:
                date_secret = date_secret_int
                secret_retenue = secret

        return {
            'secret_id': secret_retenue.attrs['ID'],
            'secret_name': secret_retenue.name,
            'date': date_secret,
        }

    def __trouver_secret_matchdate(self, secret_names, date_secrets: dict):
        for secret_name in secret_names.split(';'):
            secret_name_split = secret_name.split('.')[0:2]
            secret_name_split.append('cert')
            config_name = '.'.join(secret_name_split)
            try:
                date_secret = date_secrets[config_name]

                nom_filtre = self.idmg_tronque + '.' + secret_name + '.' + date_secret
                filtre = {'name': nom_filtre}
                secrets = self.__docker.secrets.list(filters=filtre)

                if len(secrets) != 1:
                    raise ValueError("Le secret_name ne correspond pas a un secret : %s", nom_filtre)

                secret = secrets[0]

                return {
                    'secret_id': secret.attrs['ID'],
                    'secret_name': secret.name,
                    'date': date_secret,
                }

            except KeyError:
                continue

    def __mapping(self, valeur: str):
        for cle, valeur_mappee in self.__mappings.items():
            cle = cle.upper()
            valeur = valeur.replace('${%s}' % cle, valeur_mappee)

        return valeur

    def __formatter_configuration_service(self, service_name):
        config_service = json.loads(self.charger_config('docker.cfg.' + service_name))
        self.__logger.debug("Configuration service %s : %s", service_name, str(config_service))

        dict_config_docker = self.__remplacer_variables(service_name, config_service)

        return dict_config_docker

    def __remplacer_variables(self, nom_service, config_service):
        self.__logger.debug("Remplacer variables %s" % nom_service)
        dict_config_docker = dict()

        try:
            # Name
            dict_config_docker['name'] = self.idmg_tronque + '_' + config_service['name']

            hostname = config_service.get('hostname')
            if hostname:
                dict_config_docker['hostname'] = hostname

            # Resources
            config_args = config_service.get('args')
            if config_args:
                dict_config_docker['args'] = config_args

            # Resources
            config_resources = config_service.get('resources')
            if config_resources:
                dict_config_docker['resources'] = Resources(**config_resources)

            # Restart Policy
            config_restart_policy = config_service.get('restart_policy')
            if config_restart_policy:
                dict_config_docker['restart_policy'] = RestartPolicy(**config_restart_policy)

            # Service Mode
            config_service_mode = config_service.get('mode')
            if config_service_mode:
                dict_config_docker['mode'] = ServiceMode(**config_service_mode)

            # Variables d'environnement, inclus mapping
            config_env = config_service.get('env')
            if config_env:
                # Mapping des variables
                config_env = [self.__mapping(valeur) for valeur in config_env]
                dict_config_docker['env'] = config_env

            # Constraints
            config_constraints = config_service.get('constraints')
            if config_constraints:
                dict_config_docker['constraints'] = config_constraints

            # Service labels
            config_labels = config_service.get('labels')
            if config_labels:
                updated_labels = dict()
                for key, value in config_labels.items():
                    value = self.__mapping(value)
                    updated_labels[key] = value
                dict_config_docker['labels'] = updated_labels

            # Container labels
            config_container_labels = config_service.get('container_labels')
            if config_container_labels:
                updated_labels = dict()
                for key, value in config_container_labels.items():
                    value = self.__mapping(value)
                    updated_labels[key] = value
                dict_config_docker['container_labels'] = updated_labels

            # Networks
            config_networks = config_service.get('networks')
            if config_networks:
                networks = list()
                for network in config_networks:
                    network['target'] = self.__mapping(network['target'])
                    networks.append(NetworkAttachmentConfig(**network))

                dict_config_docker['networks'] = networks

            # Configs
            config_configs = config_service.get('configs')
            dates_configs = dict()
            if config_configs:
                liste_configs = list()
                for config in config_configs:
                    self.__logger.debug("Mapping configs %s" % config)
                    config_name = config['name']
                    try:
                        config_dict = self.__trouver_config(config_name)

                        config_reference = config_dict['config_reference']
                        config_reference['filename'] = config['filename']
                        config_reference['uid'] = config.get('uid') or 0
                        config_reference['gid'] = config.get('gid') or 0
                        config_reference['mode'] = config.get('mode') or 0o444
                        liste_configs.append(ConfigReference(**config_reference))

                        dates_configs[config_name] = config_dict['date']
                    except AttributeError as ae:
                        self.__logger.error("Parametres de configuration manquants pour service %s : %s" % (config_name, str(ae)))

                dict_config_docker['configs'] = liste_configs

            # Secrets
            config_secrets = config_service.get('secrets')
            if config_secrets:
                liste_secrets = list()
                for secret in config_secrets:
                    self.__logger.debug("Mapping secret %s" % secret)
                    secret_name = secret['name']
                    if secret.get('match_config'):
                        secret_reference = self.__trouver_secret_matchdate(secret_name, dates_configs)
                    else:
                        secret_reference = self.trouver_secret(secret_name)

                    secret_reference['filename'] = secret['filename']
                    secret_reference['uid'] = secret.get('uid') or 0
                    secret_reference['gid'] = secret.get('gid') or 0
                    secret_reference['mode'] = secret.get('mode') or 0o444

                    del secret_reference['date']  # Cause probleme lors du chargement du secret
                    liste_secrets.append(SecretReference(**secret_reference))

                dict_config_docker['secrets'] = liste_secrets

            # Ports
            config_endpoint_spec = config_service.get('endpoint_spec')
            if config_endpoint_spec:
                ports = dict()
                mode = config_endpoint_spec.get('mode') or 'vip'
                for port in config_endpoint_spec.get('ports'):
                    published_port = port['published_port']
                    target_port = port['target_port']
                    protocol = port.get('protocol') or 'tcp'
                    publish_mode = port.get('publish_mode')

                    if protocol or publish_mode:
                        ports[published_port] = (target_port, protocol, publish_mode)
                    else:
                        ports[published_port] = target_port

                dict_config_docker['endpoint_spec'] = EndpointSpec(mode=mode, ports=ports)

            # Mounts
            config_mounts = config_service.get('mounts')
            if config_mounts:
                dict_config_docker['mounts'] = [self.__mapping(mount) for mount in config_mounts]

        except TypeError as te:
            self.__logger.error("Erreur mapping %s", nom_service)
            raise te

        return dict_config_docker

    def __add_node_labels(self, constraints: list):
        labels_ajoutes = dict()
        for constraint in constraints:
            if '== true' in constraint:
                valeurs = constraint.split('==')
                labels_ajoutes[valeurs[0].strip().replace('node.labels.', '')] = valeurs[1].strip()

        if len(labels_ajoutes) > 0:
            nodename = self.__docker.info()['Name']
            node_info = self.__docker.nodes.get(nodename)
            node_spec = node_info.attrs['Spec']
            labels = node_spec['Labels']
            labels.update(labels_ajoutes)
            node_info.update(node_spec)

    def executer_scripts(self, container_id: str, commande: str, tar_path: str = None):
        container = self.__docker.containers.get(container_id)

        if tar_path:
            # On copie l'archive tar et extrait dans le container
            with open(tar_path, 'rb') as fichier:
                container.put_archive('/tmp', fichier.read())

        exit_code, output = container.exec_run(commande, stream=True)
        for gen_output in output:
            for line in gen_output.decode('utf-8').split('\n'):
                self.__logger.info("Script output : %s" % line)



    @property
    def idmg_tronque(self):
        return self.__idmg[0:12]


class GestionnaireImagesDocker:

    def __init__(self, idmg: str, docker_client: docker.DockerClient):
        self.__idmg = idmg
        self._docker = docker_client
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._versions_images: dict = cast(dict, None)

    @property
    def tronquer_idmg(self):
        return self.__idmg[0:12]

    def charger_versions(self):
        raise NotImplementedError()

    def telecharger_images_docker(self):
        """
        S'assure d'avoir une version locale de chaque image - telecharge au besoin
        :return:
        """
        images_non_trouvees = list()

        self.charger_versions()

        for service in self._versions_images['images'].keys():
            # Il est possible de definir des registre specifiquement pour un service
            self.pull_image(service, images_non_trouvees)

        if len(images_non_trouvees) > 0:
            message = "Images non trouvees: %s" % str(images_non_trouvees)
            raise Exception(message)

    def telecharger_image_docker(self, nom_service):
        """
        S'assure d'avoir une version locale de chaque image - telecharge au besoin
        :return:
        """
        images_non_trouvees = list()

        self.charger_versions()

        # Il est possible de definir des registre specifiquement pour un service
        image = self.pull_image(nom_service, images_non_trouvees)

        if len(images_non_trouvees) > 0:
            message = "Images non trouvees: %s" % str(images_non_trouvees)
            raise Exception(message)

        return image

    def pull_image(self, service, images_non_trouvees):
        registries = self._versions_images.get('registries')
        images_info = self._versions_images['images']
        config = images_info[service]
        nom_image = config['image']
        tag = config['version']

        service_registries = config.get('registries')
        if service_registries is None:
            service_registries = registries
        image_locale = self.get_image_locale(nom_image, tag)
        if image_locale is None:
            image = None
            for registry in service_registries:
                if registry != '':
                    nom_image_reg = '%s/%s' % (registry, nom_image)
                else:
                    # Le registre '' represente une image docker officielle
                    nom_image_reg = nom_image

                self.__logger.info("Telecharger image %s:%s" % (nom_image, tag))
                image = self.pull(nom_image_reg, tag)
                if image is not None:
                    self.__logger.info("Image %s:%s sauvegardee avec succes" % (nom_image, tag))
                    return image  # On prend un tag au hasard

            if image is None:
                images_non_trouvees.append('%s:%s' % (nom_image, tag))

        return image_locale

    def pull(self, image_name, tag):
        """
        Effectue le telechargement d'une image.
        Cherche dans tous les registres configures.
        """

        image = None
        try:
            self.__logger.info("Telechargement image %s" % image_name)
            image = self._docker.images.pull(image_name, tag)
            self.__logger.debug("Image telechargee : %s" % str(image))
        except APIError as e:
            if e.status_code == 404:
                self.__logger.debug("Image inconnue: %s" % e.explanation)
            else:
                self.__logger.warning("Erreur api, %s" % str(e))

        return image

    def get_image_locale(self, image_name, tag, custom_registries: list = tuple()):
        """
        Verifie si une image existe deja localement. Cherche dans tous les registres.
        :param image_name:
        :param tag:
        :param custom_registries:
        :return:
        """
        self.__logger.debug("Get image locale %s:%s" % (image_name, tag))

        registries = self._versions_images['registries'].copy()
        registries.extend(custom_registries)
        registries.append('')
        for registry in registries:
            if registry != '':
                nom_image_reg = '%s/%s:%s' % (registry, image_name, tag)
            else:
                # Verifier nom de l'image sans registre (e.g. docker.io)
                nom_image_reg = '%s:%s' % (image_name, tag)

            try:
                image = self._docker.images.get(nom_image_reg)
                self.__logger.info("Image locale %s:%s trouvee" % (image_name, tag))
                return image
            except APIError:
                self.__logger.debug("Image non trouvee: %s" % nom_image_reg)

        return None

    def get_image_parconfig(self, config_key: str):
        config_values = self._versions_images['images'].get(config_key)
        self.__logger.debug("Config values pour %s: %s" % (config_key, str(config_values)))
        custom_registries = list()
        if config_values.get('registries') is not None:
            custom_registries = config_values['registries']
        image = self.get_image_locale(config_values['image'], config_values['version'], custom_registries)
        if image is not None:
            self.__logger.debug("Tags pour image %s : %s" % (config_key, str(image.tags)))
            nom_image = image.tags[0]  # On prend un tag au hasard
        else:
            self.__logger.warning("Image locale non trouvee pour config_key: %s " % config_key)
            raise ImageNonTrouvee(config_key)

        return nom_image


class GestionnaireImagesServices(GestionnaireImagesDocker):

    def __init__(self, idmg: str, docker_client: docker.DockerClient):
        super().__init__(idmg, docker_client)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._versions_images: dict = cast(dict, None)

    def charger_versions(self):
        filtre = {'name': 'docker.versions'}
        try:
            self._versions_images = json.loads(b64decode(self._docker.configs.list(filters=filtre)[0].attrs['Spec']['Data']))
        except IndexError:
            self.__logger.error(
                "Configurations de modules MilleGrille (docker.versions) ne sont pas chargee dans docker")

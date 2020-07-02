import argparse
import signal
import logging
import sys
import docker
import json
import datetime
import os
import psutil

from typing import cast
from threading import Event, Thread, BrokenBarrierError
from docker.errors import APIError
from docker.types import Resources, RestartPolicy, ServiceMode, NetworkAttachmentConfig, ConfigReference, \
    SecretReference, EndpointSpec
from base64 import b64decode

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.monitor.MonitorCertificats import GestionnaireCertificats, \
    GestionnaireCertificatsNoeudProtegeDependant, GestionnaireCertificatsNoeudProtegePrincipal
from millegrilles.monitor.MonitorCommandes import GestionnaireCommandes, GestionnaireCommandesNoeudProtegeDependant
from millegrilles.monitor.MonitorComptes import GestionnaireComptesMQ
from millegrilles.monitor.MonitorRelaiMessages import ConnexionPrincipal, ConnexionMiddleware
from millegrilles.monitor.MonitorNetworking import GestionnaireWeb
from millegrilles.util.X509Certificate import EnveloppeCleCert, \
    ConstantesGenerateurCertificat
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.monitor import MonitorConstantes


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
            config_item = self.__docker.configs.get('millegrille.configuration')
            configuration = json.loads(b64decode(config_item.attrs['Spec']['Data']))
            self._configuration_json = configuration
            self.__logger.debug("Configuration millegrille : %s" % configuration)

            specialisation = configuration.get('specialisation')
            securite = configuration.get('securite')
            if securite == '1.public':
                self.__logger.error("Noeud public, non supporte")
                raise ValueError("Noeud de type non reconnu")
            elif securite == '2.prive':
                self.__logger.error("Noeud prive, non supporte")
                raise ValueError("Noeud de type non reconnu")
            elif securite == '3.protege' and specialisation == 'dependant':
                service_monitor_classe = ServiceMonitorDependant
            elif securite == '3.protege' and specialisation == 'extension':
                self.__logger.error("Noeud d'extension, non supporte")
                raise ValueError("Noeud de type non reconnu")
            elif securite == '3.protege' and specialisation == 'principal':
                service_monitor_classe = ServiceMonitorPrincipal
            elif securite == '3.protege':
                service_monitor_classe = ServiceMonitorPrincipal
            else:
                raise ValueError("Noeud de type non reconnu")
        except docker.errors.NotFound:
            self.__logger.info("Config millegrille.configuration n'existe pas, on initialise un noeud protege principal")
            service_monitor_classe = ServiceMonitorPrincipal

        return service_monitor_classe

    def demarrer(self):
        class_noeud = self.detecter_type_noeud()
        service_monitor = class_noeud(self.__args, self.__docker, self._configuration_json)
        service_monitor.run()


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
        configuration_service = MonitorConstantes.DICT_MODULES.get(service_name)

        if configuration_service:
            # S'assurer que le certificat existe et est a date
            pass

        gestionnaire_images = GestionnaireImagesDocker(self.__idmg, self.__docker)

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
        return b64decode(self.__docker.configs.list(filters=filtre)[0].attrs['Spec']['Data'])

    def charger_config_recente(self, config_name):
        return self.__trouver_config(config_name)

    def __trouver_config(self, config_name):
        return GestionnaireModulesDocker.trouver_config(config_name, self.__idmg[0:12], self.__docker)

    @staticmethod
    def trouver_config(config_name: str, idmg_tronque: str, docker_client: docker.DockerClient):
        config_names = config_name.split(';')
        configs = None
        for config_name_val in config_names:
            filtre = {'name': idmg_tronque + '.' + config_name_val}
            configs = docker_client.configs.list(filters=filtre)
            if len(configs) > 0:
                break

        # Trouver la configuration la plus recente (par date). La meme date va etre utilise pour un secret, au besoin
        date_config: int = cast(int, None)
        config_retenue = None
        for config in configs:
            nom_config = config.name
            split_config = nom_config.split('.')
            date_config_str = split_config[-1]
            date_config_int = int(date_config_str)
            if not date_config or date_config_int > date_config:
                date_config = date_config_int
                config_retenue = config

        return {
            'config_reference': {
                'config_id': config_retenue.attrs['ID'],
                'config_name': config_retenue.name,
            },
            'date': str(date_config),
            'config': config_retenue,
        }

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

    @property
    def idmg_tronque(self):
        return self.__idmg[0:12]


class ServiceMonitor:
    """
    Service deploye dans un swarm docker en mode global qui s'occupe du deploiement des autres modules de la
    MilleGrille et du renouvellement des certificats. S'occupe de configurer les comptes RabbitMQ et MongoDB.

    Supporte aussi les MilleGrilles hebergees par l'hote.
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._args = args                                       # Arguments de la ligne de commande
        self._docker: docker.DockerClient = docker_client       # Client docker
        self._configuration_json = configuration_json           # millegrille.configuration dans docker

        self._securite: str = cast(str, None)                   # Niveau de securite de la swarm docker
        self._connexion_middleware: ConnexionMiddleware = cast(ConnexionMiddleware, None)  # Connexion a MQ, MongoDB
        self._idmg: str = cast(str, None)                       # IDMG de la MilleGrille hote

        self._socket_fifo = None  # Socket FIFO pour les commandes

        self._fermeture_event = Event()
        self._attente_event = Event()

        self._gestionnaire_certificats: GestionnaireCertificats = cast(GestionnaireCertificats, None)
        self._gestionnaire_docker: GestionnaireModulesDocker = cast(GestionnaireModulesDocker, None)
        self._gestionnaire_mq: GestionnaireComptesMQ = cast(GestionnaireComptesMQ, None)
        self._gestionnaire_commandes: GestionnaireCommandes = cast(GestionnaireCommandes, None)
        self._gestionnaire_web : GestionnaireWeb = cast(GestionnaireWeb, None)

        self.limiter_entretien = True

        self._nodename = self._docker.info()['Name']            # Node name de la connexion locale dans Docker

        # Gerer les signaux OS, permet de deconnecter les ressources au besoin
        signal.signal(signal.SIGINT, self.fermer)
        signal.signal(signal.SIGTERM, self.fermer)

        self.exit_code = 0

    def fermer(self, signum=None, frame=None):
        if signum:
            self.__logger.warning("Fermeture ServiceMonitor, signum=%d", signum)
        if not self._fermeture_event.is_set():
            self._fermeture_event.set()
            self._attente_event.set()

            try:
                self._connexion_middleware.stop()
            except Exception:
                pass

            try:
                self._docker.close()
            except Exception:
                pass

            try:
                self._gestionnaire_docker.fermer()
            except Exception:
                pass

            # Cleanup fichiers temporaires de certificats/cles
            try:
                for fichier in self._gestionnaire_certificats.certificats.values():
                    os.remove(fichier)
            except Exception:
                pass

            try:
                if self._gestionnaire_commandes:
                    self._gestionnaire_commandes.stop()
            except Exception:
                self.__logger.exception("Erreur fermeture gestionnaire commandes")

            try:
                os.remove(MonitorConstantes.PATH_FIFO)
            except Exception:
                pass

    def connecter_middleware(self):
        """
        Genere un contexte et se connecte a MQ et MongoDB.
        Lance une thread distincte pour s'occuper des messages.
        :return:
        """
        configuration = TransactionConfiguration()

        self._connexion_middleware = ConnexionMiddleware(
            configuration, self._docker, self, self._gestionnaire_certificats.certificats,
            secrets=self._args.secrets)

        try:
            self._connexion_middleware.initialiser()
            self._connexion_middleware.start()
        except BrokenBarrierError:
            self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")
            self._connexion_middleware.stop()
            self._connexion_middleware = None

    def preparer_gestionnaire_certificats(self):
        raise NotImplementedError()

    def preparer_gestionnaire_comptesmq(self):
        mode_insecure = self._args.dev
        path_secrets = self._args.secrets
        self._gestionnaire_mq = GestionnaireComptesMQ(
            self._idmg, self._gestionnaire_certificats.clecert_monitor, self._gestionnaire_certificats.certificats,
            host=self._nodename, secrets=path_secrets, insecure=mode_insecure
        )

    def preparer_gestionnaire_commandes(self):
        try:
            os.mkfifo(self._args.pipe)
        except FileExistsError:
            self.__logger.debug("Pipe %s deja cree", self._args.pipe)

        os.chmod(MonitorConstantes.PATH_FIFO, 0o620)

        # Verifier si on doit creer une instance (utilise pour override dans sous-classe)
        if self._gestionnaire_commandes is None:
            self._gestionnaire_commandes = GestionnaireCommandes(self._fermeture_event, self)

        self._gestionnaire_commandes.start()

    def _charger_configuration(self):
        # classe_configuration = self._classe_configuration()
        try:
            configuration_docker = self._docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG)
            data = b64decode(configuration_docker.attrs['Spec']['Data'])
            configuration_json = json.loads(data)
            self._idmg = configuration_json[Constantes.CONFIG_IDMG]
            self._securite = configuration_json[Constantes.DOCUMENT_INFODOC_SECURITE]

            self.__logger.debug("Configuration noeud, idmg: %s, securite: %s", self._idmg, self._securite)
        except docker.errors.NotFound as he:
            # La configuration n'existe pas
            pass

    def _classe_configuration(self):
        """
        Retourne la classe de gestion de certificat
        :return: Sous-classe de GestionnaireCertificats
        """
        raise NotImplementedError()

    def __entretien_certificats(self):
        """
        Effectue l'entretien des certificats : genere certificats manquants ou expires avec leur cle
        :return:
        """
        # MAJ date pour creation de certificats
        self._gestionnaire_certificats.maj_date()

        prefixe_certificats = self.idmg_tronque + '.pki.'
        filtre = {'name': prefixe_certificats}

        # Generer tous les certificas qui peuvent etre utilises
        roles = dict()
        for role in [info['role'] for info in MonitorConstantes.DICT_MODULES.values() if info.get('role')]:
            roles[role] = dict()

        # Charger la configuration existante
        date_renouvellement = datetime.datetime.utcnow() + datetime.timedelta(days=21)
        for config in self._docker.configs.list(filters=filtre):
            self.__logger.debug("Config : %s", str(config))
            nom_config = config.name.split('.')
            nom_role = nom_config[2]
            if nom_config[3] == 'cert' and nom_role in roles.keys():
                role_info = roles[nom_role]
                self.__logger.debug("Verification cert %s date %s", nom_role, nom_config[4])
                pem = b64decode(config.attrs['Spec']['Data'])
                clecert = EnveloppeCleCert()
                clecert.cert_from_pem_bytes(pem)
                date_expiration = clecert.not_valid_after

                expiration_existante = role_info.get('expiration')
                if not expiration_existante or expiration_existante < date_expiration:
                    role_info['expiration'] = date_expiration
                    if date_expiration < date_renouvellement:
                        role_info['est_expire'] = True
                    else:
                        role_info['est_expire'] = False

        # Generer certificats expires et manquants
        for nom_role, info_role in roles.items():
            if not info_role.get('expiration') or info_role.get('est_expire'):
                self.__logger.debug("Generer nouveau certificat role %s", nom_role)
                self._gestionnaire_certificats.generer_clecert_module(nom_role, self._nodename)

    def configurer_millegrille(self):
        besoin_initialiser = not self._idmg

        if besoin_initialiser:
            # Generer certificat de MilleGrille
            self._idmg = self._gestionnaire_certificats.generer_nouveau_idmg()

        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_PRIMAIRE.copy())
        self._gestionnaire_docker.start_events()
        self._gestionnaire_docker.add_event_listener(self)

        if besoin_initialiser:
            self._gestionnaire_docker.initialiser_millegrille()

            # Modifier service docker du service monitor pour ajouter secrets
            self._gestionnaire_docker.configurer_monitor()
            self.fermer()  # Fermer le monitor, va forcer un redemarrage du service
            raise ForcerRedemarrage("Redemarrage")

        # Generer certificats de module manquants ou expires, avec leur cle
        self._gestionnaire_certificats.charger_certificats()  # Charger certs sur disque
        self.__entretien_certificats()

        # Initialiser gestionnaire web
        self._gestionnaire_web = GestionnaireWeb(self._idmg, self)

    def _entretien_modules(self):
        if not self.limiter_entretien:
            # S'assurer que les modules sont demarres - sinon les demarrer, en ordre.
            self._gestionnaire_docker.entretien_services()

            # Entretien du middleware
            self._gestionnaire_mq.entretien()

            # Entretien web
            self._gestionnaire_web.entretien()

    def run(self):
        raise NotImplementedError()

    def verifier_load(self):
        cpu_load, cpu_load5, cpu_load10 = psutil.getloadavg()
        if cpu_load > 3.0 or cpu_load5 > 4.0:
            self.limiter_entretien = True
            self.__logger.warning("Charge de travail elevee %s / %s, entretien limite" % (cpu_load, cpu_load5))
        else:
            self.limiter_entretien = False

    @property
    def idmg_tronque(self):
        return self._idmg[0:12]

    @property
    def nodename(self):
        return self._nodename

    @property
    def identificateur(self):
        return self._nodename

    def event(self, event):
        event_json = json.loads(event)
        if event_json.get('Type') == 'container':
            if event_json.get('Action') == 'start' and event_json.get('status') == 'start':
                self.__logger.debug("Container demarre: %s", event_json)
                self._attente_event.set()

    def _preparer_csr(self):
        date_courante = datetime.datetime.utcnow().strftime(MonitorConstantes.DOCKER_LABEL_TIME)
        # Sauvegarder information pour CSR, cle
        label_cert_millegrille = self.idmg_tronque + '.pki.millegrille.cert.' + date_courante
        self._docker.configs.create(name=label_cert_millegrille, data=json.dumps(self._configuration_json['pem']))

    @property
    def gestionnaire_mq(self):
        return self._gestionnaire_mq

    @property
    def gestionnaire_mongo(self):
        return self._connexion_middleware.get_gestionnaire_comptes_mongo

    @property
    def gestionnaire_docker(self) -> GestionnaireModulesDocker:
        return self._gestionnaire_docker

    @property
    def gestionnaire_commandes(self):
        return self._gestionnaire_commandes

    @property
    def gestionnaire_certificats(self):
        return self._gestionnaire_certificats

    @property
    def generateur_transactions(self):
        return self._connexion_middleware.generateur_transactions

    def rediriger_messages_downstream(self, nom_domaine: str, exchanges_routing: dict):
        raise NotImplementedError()


class ServiceMonitorPrincipal(ServiceMonitor):
    """
    ServiceMonitor pour noeud protege principal
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def run(self):
        self.__logger.info("Demarrage du ServiceMonitor")

        try:
            self._charger_configuration()
            self.preparer_gestionnaire_certificats()
            self.configurer_millegrille()
            self.preparer_gestionnaire_comptesmq()
            self.preparer_gestionnaire_commandes()

            while not self._fermeture_event.is_set():
                self._attente_event.clear()

                try:
                    self.__logger.debug("Cycle entretien ServiceMonitor")

                    self.verifier_load()

                    self._entretien_modules()

                    if not self._connexion_middleware:
                        try:
                            self.connecter_middleware()
                        except BrokenBarrierError:
                            self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")

                    self.__logger.debug("Fin cycle entretien ServiceMonitor")
                except Exception:
                    self.__logger.exception("ServiceMonitor: erreur generique")
                finally:
                    self._attente_event.wait(30)

        except ForcerRedemarrage:
            self.__logger.info("Configuration initiale terminee, fermeture pour redemarrage")
            self.exit_code = ConstantesServiceMonitor.EXIT_REDEMARRAGE

        except Exception:
            self.__logger.exception("Erreur demarrage ServiceMonitor, on abandonne l'execution")

        self.__logger.info("Fermeture du ServiceMonitor")
        self.fermer()

        # Fermer le service monitor, retourne exit code pour shell script
        sys.exit(self.exit_code)

    def preparer_gestionnaire_certificats(self):
        params = dict()
        if self._args.dev:
            params['insecure'] = True
        if self._args.secrets:
            params['secrets'] = self._args.secrets
        self._gestionnaire_certificats = GestionnaireCertificatsNoeudProtegePrincipal(self._docker, self, **params)

    def preparer_gestionnaire_commandes(self):
        self._gestionnaire_commandes = GestionnaireCommandes(self._fermeture_event, self)

        super().preparer_gestionnaire_commandes()  # Creer pipe et demarrer

    def rediriger_messages_downstream(self, nom_domaine: str, exchanges_routing: dict):
        pass  # Rien a faire pour le monitor principal


class ServiceMonitorDependant(ServiceMonitor):
    """
    ServiceMonitor pour noeud protege dependant
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__event_attente = Event()

        self.__connexion_principal: ConnexionPrincipal = cast(ConnexionPrincipal, None)

    def fermer(self, signum=None, frame=None):
        super().fermer(signum, frame)
        self.__event_attente.set()

    def trigger_event_attente(self):
        self.__event_attente.set()

    def run(self):
        self.__logger.debug("Execution noeud dependant")
        self._charger_configuration()
        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_DEPENDANT.copy())
        self._gestionnaire_docker.start_events()
        self._gestionnaire_docker.add_event_listener(self)
        self.preparer_gestionnaire_certificats()

        methode_run = self.__determiner_type_run()
        methode_run()  # Excuter run

    def __determiner_type_run(self):
        # Verifier si le certificat de millegrille a ete charge
        try:
            info_cert_millegrille = self.gestionnaire_docker.trouver_config(
                'pki.millegrille.cert', self.idmg_tronque, self._docker)
            self.__logger.debug("Cert millegrille deja charge, date %s" % info_cert_millegrille['date'])
        except AttributeError:
            self.__logger.info("Run initialisation noeud dependant")
            return self.run_configuration_initiale

        # Le certificat de millegrille est charge, s'assurer que la cle de monitor est generee
        # Il est anormal que le cert millegrille soit charge et la cle de monitor absente, mais c'est supporte
        try:
            label_key = 'pki.' + ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT + '.key'
            info_cle_monitor = self.gestionnaire_docker.trouver_secret(label_key)
            self.__logger.debug("Cle monitor deja chargee, date %s" % info_cle_monitor['date'])
        except AttributeError:
            self.__logger.warning("Cle secrete monitor manquante, run initialisation noeud dependant")
            return self.run_configuration_initiale

        # Verifier si le certificat de monitor correspondant a la cle est charge

        return self.run_monitor

    def run_configuration_initiale(self):
        """
        Sert a initialiser le noeud protege dependant.
        Termine son execution immediatement apres creation du CSR.
        :return:
        """

        self.__logger.info("Run configuration initiale, (mode insecure: %s)" % self._args.dev)

        # Creer CSR pour le service monitor
        self._gestionnaire_certificats.generer_csr(
            ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT, insecure=self._args.dev)

        # Generer mots de passe
        self._gestionnaire_certificats.generer_motsdepasse()

        # Sauvegarder information pour CSR, cle
        cert_millegrille = self._configuration_json['pem'].encode('utf-8')
        self._gestionnaire_certificats.ajouter_config(
            name='pki.millegrille.cert', data=cert_millegrille)

        self._gestionnaire_docker.initialiser_millegrille()

        print("Preparation CSR du noeud dependant terminee")
        print("Redemarrer le service monitor")

    def run_monitor(self):
        """
        Execution du monitor.
        :return:
        """
        self.__logger.info("Run monitor noeud protege dependant")

        # Activer ecoute des commandes
        self.preparer_gestionnaire_commandes()

        # Initialiser cles, certificats disponibles
        self._gestionnaire_certificats.charger_certificats()  # Charger certs sur disque

        self._attendre_certificat_monitor()  # S'assurer que le certificat du monitor est correct, l'attendre au besoin
        self._initialiser_middleware()       # S'assurer que les certificats du middleware sont corrects
        self._run_entretien()                # Mode d'operation de base, lorsque le noeud est bien configure

    def _attendre_certificat_monitor(self):
        """
        Mode d'attente de la commande avec le certificat signe du monitor.
        :return:
        """
        self.__logger.info("Verifier et attendre certificat du service monitor")

        clecert_monitor = self._gestionnaire_certificats.clecert_monitor
        if not clecert_monitor.cert:
            while not self.__event_attente.is_set():
                self.__logger.info("Attente du certificat de monitor dependant")
                self.__event_attente.wait(120)

        self.__logger.debug("Certificat monitor valide jusqu'a : %s" % clecert_monitor.not_valid_after)

        self.__logger.info("Certificat du service monitor pret")

    def _initialiser_middleware(self):
        """
        Mode de creation des certificats du middleware (MQ, Mongo, MongoExpress)
        :return:
        """
        self.__logger.info("Verifier et attendre certificats du middleware")

        # Charger certificats - copie les certs sous /tmp pour connecter a MQ
        self._gestionnaire_certificats.charger_certificats()

        # Connecter au MQ principal
        self.__connexion_principal = ConnexionPrincipal(self._docker, self)
        self.__connexion_principal.connecter()

        # Confirmer que les cles mq, mongo, mongoxp ont ete crees
        liste_csr = list()
        for role in MonitorConstantes.CERTIFICATS_REQUIS_DEPENDANT:
            label_cert = 'pki.%s.cert' % role
            try:
                self._gestionnaire_docker.trouver_config(label_cert, self.idmg_tronque, self._docker)
            except AttributeError:
                label_key = 'pki.%s.key' % role
                fichier_csr = 'pki.%s.csr.pem' % role
                try:
                    self._gestionnaire_docker.trouver_secret(label_key)
                    path_fichier = os.path.join(MonitorConstantes.PATH_PKI, fichier_csr)
                    with open(path_fichier, 'r') as fichier:
                        csr = fichier.read()
                except AttributeError:
                    # Creer la cle, CSR correspondant
                    inserer_cle = role not in ['mongo']
                    info_csr = self._gestionnaire_certificats.generer_csr(role, insecure=self._args.dev, inserer_cle=inserer_cle)
                    csr = str(info_csr['request'], 'utf-8')
                    if role == 'mongo':
                        self._gestionnaire_certificats.memoriser_cle(role, info_csr['cle_pem'])
                liste_csr.append(csr)

        if len(liste_csr) > 0:
            self.__event_attente.clear()
            commande = {
                'liste_csr': liste_csr,
            }
            # Transmettre commande de signature de certificats, attendre reponse
            while not self.__event_attente.is_set():
                self.__connexion_principal.generateur_transactions.transmettre_commande(
                    commande,
                    'commande.MaitreDesCles.%s' % Constantes.ConstantesMaitreDesCles.COMMANDE_SIGNER_CSR,
                    correlation_id=ConstantesServiceMonitor.CORRELATION_CERTIFICAT_SIGNE,
                    reply_to=self.__connexion_principal.reply_q
                )
                self.__logger.info("Attente certificats signes du middleware")
                self.__event_attente.wait(120)

        self.preparer_gestionnaire_comptesmq()
        self.__logger.info("Certificats du middleware prets")

    def _run_entretien(self):
        """
        Mode d'operation de base du monitor, lorsque toute la configuration est completee.
        :return:
        """
        self.__logger.info("Debut boucle d'entretien du service monitor")

        while not self._fermeture_event.is_set():
            self._attente_event.clear()

            try:
                self.__logger.debug("Cycle entretien ServiceMonitor")

                self.verifier_load()

                if not self._connexion_middleware:
                    try:
                        self.connecter_middleware()
                        self._connexion_middleware.set_relai(self.__connexion_principal)
                        self.__connexion_principal.initialiser_relai_messages(self._connexion_middleware.relayer_message)
                    except BrokenBarrierError:
                        self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")

                self._entretien_modules()

                self.__logger.debug("Fin cycle entretien ServiceMonitor")
            except Exception:
                self.__logger.exception("ServiceMonitor: erreur generique")
            finally:
                self._attente_event.wait(30)

        self.__logger.info("Fin execution de la boucle d'entretien du service monitor")

    def connecter_middleware(self):
        super().connecter_middleware()

    def __charger_cle(self):
        if self._args.dev:
            path_cle = '/var/opt/millegrilles/pki/servicemonitor.key.pem'
        else:
            path_cle = '/run/secrets/pki.monitor.key.pem'

        with open(path_cle, 'rb') as fichier:
            cle_bytes = fichier.read()

    def preparer_gestionnaire_certificats(self):
        params = dict()
        if self._args.dev:
            params['insecure'] = True
        if self._args.secrets:
            params['secrets'] = self._args.secrets
        self._gestionnaire_certificats = GestionnaireCertificatsNoeudProtegeDependant(self._docker, self, **params)

    def preparer_gestionnaire_commandes(self):
        self._gestionnaire_commandes = GestionnaireCommandesNoeudProtegeDependant(self._fermeture_event, self)

        super().preparer_gestionnaire_commandes()  # Creer pipe et demarrer

    def inscrire_domaine(self, nom_domaine: str, exchanges_routing: dict):
        self._connexion_middleware.rediriger_messages_domaine(nom_domaine, exchanges_routing)

    def rediriger_messages_downstream(self, nom_domaine: str, exchanges_routing: dict):
        self.__connexion_principal.enregistrer_domaine(nom_domaine, exchanges_routing)


class GestionnaireImagesDocker:

    def __init__(self, idmg: str, docker_client: docker.DockerClient):
        self.__idmg = idmg
        self.__docker = docker_client
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self.__versions_images: dict = cast(dict, None)

    @property
    def tronquer_idmg(self):
        return self.__idmg[0:12]

    def charger_versions(self):
        filtre = {'name': 'docker.versions'}
        try:
            self.__versions_images = json.loads(b64decode(self.__docker.configs.list(filters=filtre)[0].attrs['Spec']['Data']))
        except IndexError:
            self.__logger.error(
                "Configurations de modules MilleGrille (docker.versions) ne sont pas chargee dans docker")

    def telecharger_images_docker(self):
        """
        S'assure d'avoir une version locale de chaque image - telecharge au besoin
        :return:
        """
        images_non_trouvees = list()

        self.charger_versions()

        for service in self.__versions_images['images'].keys():
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
        registries = self.__versions_images['registries']
        config = self.__versions_images['images'][service]
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
            image = self.__docker.images.pull(image_name, tag)
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

        registries = self.__versions_images['registries'].copy()
        registries.extend(custom_registries)
        registries.append('')
        for registry in registries:
            if registry != '':
                nom_image_reg = '%s/%s:%s' % (registry, image_name, tag)
            else:
                # Verifier nom de l'image sans registre (e.g. docker.io)
                nom_image_reg = '%s:%s' % (image_name, tag)

            try:
                image = self.__docker.images.get(nom_image_reg)
                self.__logger.info("Image locale %s:%s trouvee" % (image_name, tag))
                return image
            except APIError:
                self.__logger.debug("Image non trouvee: %s" % nom_image_reg)

        return None

    def get_image_parconfig(self, config_key: str):
        config_values = self.__versions_images['images'].get(config_key)
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


class ImageNonTrouvee(Exception):

    def __init__(self, image, t=None, obj=None):
        super().__init__(t, obj)
        self.image = image


class ForcerRedemarrage(Exception):
    pass


# Section main
if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format=MonitorConstantes.SERVICEMONITOR_LOGGING_FORMAT)
    logging.getLogger(ServiceMonitor.__name__).setLevel(logging.INFO)

    # ServiceMonitor().run()
    InitialiserServiceMonitor().demarrer()

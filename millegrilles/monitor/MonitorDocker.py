import json
import logging
import os
import datetime
import socket
import docker
import re
import secrets

from os import path

from uuid import uuid4
from base64 import b64encode, b64decode
from threading import Event, Thread
from typing import cast, Optional
from docker.client import DockerClient
from docker.errors import APIError
from docker.types import SecretReference, NetworkAttachmentConfig, Resources, RestartPolicy, ServiceMode, \
    ConfigReference, EndpointSpec, Mount

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor, ConstantesGenerateurCertificat
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.MonitorConstantes import ImageNonTrouvee, ExceptionExecution, PkiCleNonTrouvee, ForcerRedemarrage
from millegrilles.monitor.MonitorConstantes import GenerationCertificatNonSupporteeException
from millegrilles.SecuritePKI import GenerateurEd25519, GenerateurRsa
from millegrilles.util import IpUtils


class GestionnaireModulesDocker:

    def __init__(self,
                 idmg: str,
                 docker_client: DockerClient,
                 fermeture_event: Event,
                 modules_requis: list,
                 service_monitor,
                 configuration_services=MonitorConstantes.DICT_MODULES_PROTEGES,
                 **kwargs):
        self.__idmg = idmg
        self.__docker = docker_client
        self.configuration_json = None
        self.__fermeture_event = fermeture_event
        self.__thread_events: Thread = cast(Thread, None)
        self.__event_stream = None
        self.__modules_requis = modules_requis
        self.__hebergement_actif = False
        self.__service_monitor = service_monitor
        self.__configuration_services = configuration_services

        self.__insecure = kwargs.get('insecure') or False
        self.__secrets = kwargs.get('secrets')  # Repertoire des secrets
        self.__rep_nginx = '/var/opt/millegrilles/nginx'  # Repertoire dev nginx, mode insecure
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('trace.' + __name__ + '.' + self.__class__.__name__)

        fqdn = self.hostname

        try:
            self.__local_ips = GestionnaireModulesDocker.get_local_ips()
        except:
            self.__local_ips = dict()

        try:
            acme_config = json.loads(self.charger_config('acme.configuration'))
            hostname_domaine = acme_config.get('domain') or fqdn
        except:
            self.__logger.warning("Erreur chargement acme.config pour trouver domaine, host = %s" % fqdn)
            hostname_domaine = fqdn

        self.__mappings = {
            'IDMG': self.__idmg,
            'MONGO_INITDB_ROOT_USERNAME': 'admin',
            'MOUNTS': '/var/opt/millegrilles/mounts',
            'NODENAME': self.nodename,
            'HOSTNAME': fqdn,
            'HOSTNAME_DOMAINE': hostname_domaine,
            'NGINX_CONFIG_VOLUME': '/var/opt/millegrilles/nginx/modules',
            'NGINX_HTML_VOLUME': 'nginx-html',
            'NGINX_DATA_VOLUME': 'nginx-data',
            # 'MQ_HOST': '',  # Ajoute automatiquement
            # 'MQ_PORT': '',  # Ajoute automatiquement
            'HOST_IPV4': self.__local_ips.get('ipv4') or '127.0.0.1',
            'HOST_IPV6': self.__local_ips.get('ipv6') or '::1',
        }

        if self.__insecure:
            self.__mappings['NGINX_CONFIG_VOLUME'] = path.join(self.__rep_nginx, 'modules')
            self.__mappings['NGINX_HTML_VOLUME'] = path.join(self.__rep_nginx, 'html')
            self.__mappings['NGINX_DATA_VOLUME'] = path.join(self.__rep_nginx, 'data')

        self.__event_listeners = list()

        self.__intervalle_entretien_comptes = datetime.timedelta(minutes=5)
        self.__derniere_creation_comptes = datetime.datetime.utcnow() - self.__intervalle_entretien_comptes + datetime.timedelta(seconds=15)

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
            self.__logger_verbose.debug("Event : %s", str(event))
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
        network_name = 'millegrille_net'
        try:
            self.__docker.networks.create(name=network_name, scope="swarm", driver="overlay", attachable=True)
        except APIError as apie:
            if apie.status_code == 409:
                self.__logger.info("Reseau %s deja cree" % network_name)
            else:
                raise apie

        # Creer repertoire generique /millegrilles
        # S'assurer que le repertoire d'hebergement de la MilleGrille est cree
        path_millegrilles = os.path.join(Constantes.DEFAUT_VAR_MILLEGRILLES)
        try:
            os.mkdir(path_millegrilles, mode=0o770)
        except FileExistsError:
            self.__logger.debug("Repertoire %s existe, ok" % path_millegrilles)

        try:
            self.charger_params_dynamiques()
        except Exception as e:
            self.__logger.warning("Erreur chargement params dynamiques pour docker : %s" % str(e))

    def initialiser_noeud(self, idmg=None):
        if idmg:
            self.idmg = idmg

        if not self.__service_monitor.noeud_id:
            noeud_id = str(uuid4())
            self.sauvegarder_config(ConstantesServiceMonitor.DOCKER_CONFIG_NOEUD_ID, noeud_id)
            self.__service_monitor.set_noeud_id(noeud_id)
        
        self.initialiser_millegrille()

    def configurer_monitor(self, env_params: list = None):
        """
        Ajoute les element de configuration generes (e.g. secrets).
        :return:
        """
        noms_secrets = {
            'passwd.mongo': ConstantesServiceMonitor.FICHIER_MONGO_MOTDEPASSE,
            'passwd.mq': ConstantesServiceMonitor.FICHIER_MQ_MOTDEPASSE,
            'passwd.mongoxpweb': ConstantesServiceMonitor.FICHIER_MONGOXPWEB_MOTDEPASSE,
            # ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_KEY: ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_KEY + '.pem',
            #ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_PASSWD: ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_PASSWD + '.txt',
            #ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_KEY: ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_KEY + '.pem',
        }

        liste_secrets = list()
        # try:
        #     info_clecert_intermediaire = self.__service_monitor.gestionnaire_certificats.reconfigurer_clecert('pki.intermediaire.cert', True)
        #     liste_secrets.extend(info_clecert_intermediaire['secrets'])
        # except AttributeError:
        #     self.__logger.info("On n'a pas de certificat intermediaire - utiliser nom du secret")
        #     noms_secrets[ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_PASSWD] = ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_PASSWD + '.txt'
        #     noms_secrets[ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_KEY] = ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_KEY + '.pem'

        try:
            info_clecert_monitor = self.__service_monitor.gestionnaire_certificats.reconfigurer_clecert('pki.monitor.cert')
            liste_secrets.extend(info_clecert_monitor['secrets'])
        except AttributeError:
            self.__logger.warning("Certificat monitor n'est pas encore configure")
            noms_secrets[ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_KEY] = ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_KEY + '.pem'

        for nom_secret, nom_fichier in noms_secrets.items():
            try:
                self.__logger.debug("Preparer secret %s pour service monitor", nom_secret)
                secret_reference = self.trouver_secret(nom_secret)
                secret_reference['filename'] = nom_fichier
                secret_reference['uid'] = 0
                secret_reference['gid'] = 0
                secret_reference['mode'] = 0o444

                del secret_reference['date']

                liste_secrets.append(SecretReference(**secret_reference))
            except PkiCleNonTrouvee:
                self.__logger.warning("Erreur chargement secret %s" % nom_secret)

        # Trouver nom du certificat le plus recent et charger la cle correspondante
        # try:
        #     config_cert = self.__trouver_config("pki.monitor.cert")
        #     secret_name_val = config_cert['config_reference']['config_name'].replace('cert', 'key')
        #     filtre_secrets = {'name': secret_name_val}
        #     secrets = self.__docker.secrets.list(filters=filtre_secrets)
        #     secret_retenue = secrets[0]
        #     self.__logger.info("Configuration cle %s pour monitor" % secret_retenue.name)
        #     secret_reference = {
        #         'secret_id': secret_retenue.attrs['ID'],
        #         'secret_name': secret_retenue.name,
        #         'filename': ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_KEY + '.pem',
        #         'uid': 0,
        #         'gid': 0,
        #         'mode': 0o444,
        #     }
        #
        #     liste_secrets.append(SecretReference(**secret_reference))
        # except AttributeError:
        #     self.__logger.info("configurer_monitor: Certificat de monitor n'existe pas")

        # network = NetworkAttachmentConfig(target='mg_net' % self.__idmg)

        # Ajouter secrets au service monitor
        filtre = {'name': 'monitor'}
        services_list = self.__docker.services.list(filters=filtre)
        try:
            if self.__insecure:
                # Mettre a jour les symlinks pour les fichiers sous /secrets
                for s in liste_secrets:
                    secret_name = s.get('SecretName')
                    path_original = path.join(self.__secrets, secret_name)
                    path_symlink = path.join(self.__secrets, s.get('File')['Name'])

                    try:
                        os.remove(path_symlink)
                    except FileNotFoundError:
                        pass  # OK

                    os.symlink(path_original, path_symlink)

            service_monitor = services_list[0]
            self.__logger.info("configurer_monitor Mise a jour monitor avec secrets")
            if len(liste_secrets) > 0:
                service_monitor.update(secrets=liste_secrets, env=env_params)
                raise ForcerRedemarrage("Redemarrage apres rotation secrets")

        except IndexError:
            self.__logger.error("Erreur configuration service monitor avec nouvelles valeurs (OK si dev)")

    def entretien_services(self, nom_service: str = None):
        """
        Verifie si les services sont actifs, les demarre au besoin.
        :param nom_service: Nom du service a entretenir (opt)
        :return:
        """
        try:
            self.charger_params_dynamiques()
        except Exception as e:
            self.__logger.warning("Erreur chargement params dynamiques pour docker : %s" % str(e))

        filtre = dict()
        if nom_service is not None:
            filtre = {'name': nom_service}
        # liste_services = self.__docker.services.list(filters=filtre)
        liste_services = self.__docker.services.list(filters=filtre)
        dict_services = dict()
        for service in liste_services:
            # Enlever prefix avec IDMG
            # service_name = '_'.join(service.name.split('_')[1:])
            service_name = service.name
            dict_services[service_name] = service

        entretien_compte_complete = True
        dict_configurations_services = self.get_configuration_services()
        for service_name in self.__modules_requis:
            if nom_service is not None and service_name != nom_service:
                # On skip ce service
                continue

            try:
                params = dict_configurations_services[service_name]
                service = dict_services.get(service_name)
                if not service:
                    try:
                        self.demarrer_service(service_name, **params)
                    except IndexError:
                        self.__logger.error("Configuration service docker.cfg.%s introuvable" % service_name)
                    entretien_compte_complete = False
                    break  # On demarre un seul service a la fois, on attend qu'il soit pret
                else:
                    # Verifier etat service
                    self.verifier_etat_service(service)

                    if self.__derniere_creation_comptes < datetime.datetime.utcnow() - self.__intervalle_entretien_comptes:
                        try:
                            self.creer_comptes_service(service)
                        except:
                            entretien_compte_complete = False
            except Exception:
                self.__logger.exception("Erreur verification etat service %s" % service_name)

        # Liste des applications container (sans service)
        liste_applications_arretees = self.__docker.containers.list(
            filters={'status': 'exited', 'label': 'application'})
        for container in liste_applications_arretees:
            try:
                self.__logger.info("Redemarrer container application " + container.name)
                container.start()
            except APIError:
                self.__logger.exception("Erreur redemarrage container application : " + container.name)

        if entretien_compte_complete:
            self.__derniere_creation_comptes = datetime.datetime.utcnow()

    def charger_params_dynamiques(self):
        info_mq = self.__service_monitor.get_info_connexion_mq()
        self.__mappings.update(info_mq)

    def demarrer_service(self, service_name: str, **kwargs):
        self.__logger.info("Demarrage service %s", service_name)

        configuration_service = kwargs.get('config')
        if not configuration_service:
            configuration_service = MonitorConstantes.DICT_MODULES_PROTEGES.get(service_name) or \
                                    MonitorConstantes.DICT_MODULES_PRIVES.get(service_name) or \
                                    MonitorConstantes.DICT_MODULES_PUBLICS.get(service_name) or \
                                    MonitorConstantes.DICT_MODULES_INSTALLATION.get(service_name)

        gestionnaire_images = kwargs.get('images')
        if not gestionnaire_images:
            gestionnaire_images = GestionnaireImagesServices(self.__idmg, self.__docker)

        if configuration_service:
            # S'assurer que le certificat existe, est a date et que le compte est cree
            # cle_config_service = configuration_service.get('role') or configuration_service.get('nom')
            cle_config_service = configuration_service.get('nom_config') or service_name
            if cle_config_service:
                configuration_service_meta = self.charger_config_recente('docker.cfg.' + cle_config_service)
                config_attrs = configuration_service_meta['config'].attrs
                configuration_service_json = json.loads(b64decode(config_attrs['Spec']['Data']))

                certificat_compte_cle = configuration_service_json.get('certificat_compte')
                if certificat_compte_cle:
                    try:
                        self.creer_compte(certificat_compte_cle)
                    except AttributeError:
                        self.__logger.info("Le certificat n'existe pas, on va le creer : %s" % certificat_compte_cle)
                        try:
                            info_monitor = self.__service_monitor.get_info_monitor()
                            fqdn_noeud = info_monitor['fqdn_detecte']
                            try:
                                domaine_noeud = info_monitor['domaine']
                            except KeyError:
                                domaine_noeud = fqdn_noeud

                            enveloppe = self.__service_monitor.gestionnaire_certificats.generer_clecert_module(
                                cle_config_service, self.__service_monitor.noeud_id, liste_dns=[fqdn_noeud, domaine_noeud])
                        except GenerationCertificatNonSupporteeException:
                            self.__logger.warning("Application installee sans generer un certificat (noeud prive ou public)")
                        else:
                            self.creer_compte(certificat_compte_cle)

                generateurs = configuration_service_json.get('generer')
                if generateurs is not None:
                    # S'assurer que les valeurs sont generees
                    self.generer_valeurs(generateurs)

        nom_image_docker = kwargs.get('nom_image') or service_name

        configuration = dict()
        try:
            image = gestionnaire_images.telecharger_image_docker(nom_image_docker, **kwargs)

            # Prendre un tag au hasard
            image_tag = image.tags[0]

            configuration = self.__formatter_configuration_service(service_name, application=kwargs.get('application'))

            command = configuration_service.get('command')

            constraints = configuration.get('constraints')
            if constraints:
                self.__add_node_labels(constraints)

            self.__docker.services.create(image_tag, command=command, **configuration)
        except KeyError as ke:
            self.__logger.error("Erreur chargement image %s, key error sur %s" % (nom_image_docker, str(ke)))
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail erreur chargement image :\n%s", json.dumps(configuration, indent=2))
        except (AttributeError, ValueError) as ae:
            self.__logger.error("Erreur configuration service %s : %s" % (service_name, str(ae)))
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail erreur configuration service " + service_name)
        #except APIError as apie:
        #    # self.__logger.exception("Detail erreur chargement image :\n%s", json.dumps(configuration, indent=2))
        #    # raise apie
        #    if apie.status_code == 409:
        #        self.__logger.info("Service %s deja demarre" % service_name)
        #        return True
        #    else:
        #        self.__logger.exception("Erreur demarrage service %s" % service_name)
        #        raise apie

    def generer_valeurs(self, generateurs: list):
        """
        S'assure que les valeurs dans la liste sont generees
        :param generateurs:
        :return:
        """
        for generateur in generateurs:
            self.__logger.info("Verifier si la valeur %s est generee" % str(generateur))
            config_name = generateur.get('config')
            secret_name = generateur.get('secret')

            # Verifier si le secret ou config existe
            doit_generer = False
            if config_name is not None:
                try:
                    self.__trouver_config(config_name)
                except AttributeError:
                    doit_generer = True
            if secret_name is not None:
                try:
                    self.trouver_secret(secret_name)
                except PkiCleNonTrouvee:
                    doit_generer = True

            if doit_generer:
                type_generateur = generateur['generateur']
                if type_generateur == 'ed25519':
                    self.generer_cle_ed25519(generateur)
                elif type_generateur == 'rsa':
                    self.generer_cle_rsa(generateur)
                elif type_generateur == 'motdepasse':
                    self.generer_motdepasse(generateur)

    def generer_cle_ed25519(self, params: dict):
        format_cle = params['format']
        nom_secret = params.get('secret')
        nom_config = params.get('config')

        if format_cle == 'openssh':
            generateur = GenerateurEd25519()
            valeur = generateur.generer_private_openssh()
        else:
            raise ValueError('Type cle inconnu : %s', format_cle)

        if nom_secret is not None:
            self.sauvegarder_secret(nom_secret, valeur, ajouter_date=True)
        elif nom_config is not None:
            self.sauvegarder_config(nom_config, valeur)

    def generer_cle_rsa(self, params: dict):
        format_cle = params['format']
        nom_secret = params.get('secret')
        nom_config = params.get('config')

        if format_cle == 'openssh':
            generateur = GenerateurRsa()
            valeur = generateur.generer_private_openssh()
        elif format_cle == 'openssh_ed25519':
            generateur = GenerateurEd25519()
            valeur = generateur.generer_private_openssh()
        else:
            raise ValueError('Type cle inconnu : %s', format_cle)

        if nom_secret is not None:
            self.sauvegarder_secret(nom_secret, valeur, ajouter_date=True)
        elif nom_config is not None:
            self.sauvegarder_config(nom_config, valeur)

    def generer_motdepasse(self, params: dict):
        longueur = params.get('len') or 32
        nom_secret = params['secret']

        secret_bytes = secrets.token_bytes(longueur)
        secret_str = b64encode(secret_bytes)
        valeur = secret_str[0:longueur]  # Tronquer a la longueur demandee

        if nom_secret is not None:
            self.sauvegarder_secret(nom_secret, valeur, ajouter_date=True)

    def reconfigurer_service(self, service_name: str, docker_service=None, **kwargs):
        self.__logger.info("Demarrage service %s", service_name)

        if docker_service is None:
            docker_service = self.get_service(service_name)

        configuration_service = kwargs.get('config')
        if not configuration_service:
            configuration_service = MonitorConstantes.DICT_MODULES_PROTEGES.get(service_name)

        gestionnaire_images = kwargs.get('images')
        if not gestionnaire_images:
            gestionnaire_images = GestionnaireImagesServices(self.__idmg, self.__docker)

        if configuration_service:
            # S'assurer que le certificat existe, est a date et que le compte est cree
            cle_config_service = configuration_service.get('role') or configuration_service.get('nom')
            if cle_config_service:
                configuration_service_meta = self.charger_config_recente('docker.cfg.' + cle_config_service)
                config_attrs = configuration_service_meta['config'].attrs
                configuration_service_json = json.loads(b64decode(config_attrs['Spec']['Data']))
                certificat_compte_cle = configuration_service_json.get('certificat_compte')
                if certificat_compte_cle:
                    self.creer_compte(certificat_compte_cle)

        nom_image_docker = kwargs.get('nom_image') or service_name

        configuration = dict()
        try:
            image = gestionnaire_images.telecharger_image_docker(nom_image_docker)

            # Prendre un tag au hasard
            try:
                image_tag = image.tags[0]
                configuration['image'] = image_tag
            except:
                pass  # On ne met pas a jour l'image

            configuration = self.__formatter_configuration_service(service_name, application=service_name)

            constraints = configuration.get('constraints')
            if constraints:
                self.__add_node_labels(constraints)

            # Utiliser service existant pour integrer la nouvelle configuration
            try:
                docker_service.update(**configuration)
            except APIError as ae:
                self.__logger.error("Erreur maj service, on essaie de recharger : %s" % ae)
                docker_service = self.get_service(service_name)
                docker_service.update(**configuration)

            # self.__docker.services.create(image_tag, command=command, **configuration)
            return docker_service

        except KeyError as ke:
            self.__logger.error("Erreur chargement image %s, key error sur %s" % (nom_image_docker, str(ke)))
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail erreur chargement image :\n%s", json.dumps(configuration, indent=2))
        except AttributeError as ae:
            self.__logger.error("Erreur configuration service %s : %s" % (service_name, str(ae)))
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail erreur configuration service " + service_name)

    def demarrer_container(self, container_name: str, config: dict, **kwargs):
        self.__logger.info("Demarrage container %s", container_name)

        gestionnaire_images = kwargs.get('images')
        if not gestionnaire_images:
            gestionnaire_images = GestionnaireImagesServices(self.__idmg, self.__docker)

        # S'assurer que le certificat existe, est a date et que le compte est cree
        cle_config_service = config.get('role') or config.get('nom')
        if cle_config_service:
            configuration_service_meta = self.charger_config_recente('docker.cfg.' + cle_config_service)
            config_attrs = configuration_service_meta['config'].attrs
            configuration_service_json = json.loads(b64decode(config_attrs['Spec']['Data']))
            certificat_compte_cle = configuration_service_json.get('certificat_compte')
            if certificat_compte_cle:
                self.creer_compte(certificat_compte_cle)

        nom_image_docker = kwargs.get('nom_image') or config.get('image') or container_name

        self.__logger.debug("Deploiement image %s, config: %s" % (nom_image_docker, config))

        configuration = dict()
        try:
            image = gestionnaire_images.telecharger_image_docker(nom_image_docker)

            # Prendre un tag au hasard
            image_tag = image.tags[0]

            config_image = kwargs.get('config_image')
            certificat_volume = config_image.get('certificat_volume')
            certificat_compte = config_image.get('certificat_compte')
            # if config_image is not None:
            #     self.__regenerer_certificat_container(container_name, kwargs.get('config_image'))
            #     certificat_volume = config_image.get('certificat_volume')
            # else:
            #     certificat_volume = None
            configuration = self.__formatter_configuration_container(
                container_name, config,
                application=kwargs.get('application'),
                certificat_volume=certificat_volume,
                certificat_compte=certificat_compte
            )

            self.__logger.debug("Configuration du container: %s" % configuration)

            command = config.get('command')

            self.__docker.containers.run(image_tag, command=command, **configuration)
        except KeyError as ke:
            self.__logger.error("Erreur chargement image %s, key error sur %s" % (nom_image_docker, str(ke)))
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail erreur chargement image :\n%s", json.dumps(configuration, indent=2))
        except AttributeError as ae:
            self.__logger.error("Erreur configuration service %s : %s" % (container_name, str(ae)))
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail erreur configuration service " + container_name)
        except APIError as apie:
            self.__logger.exception("Detail erreur chargement image :\n%s", json.dumps(configuration, indent=2))
            raise apie

    def maj_service(self, service_name: str, **kwargs):
        service_inst = self.__docker.services.list(filters={'name': service_name})[0]

        configuration_service = kwargs.get('config')
        if not configuration_service:
            configuration_service = MonitorConstantes.DICT_MODULES_PROTEGES.get(service_name)

        gestionnaire_images = kwargs.get('images')
        if not gestionnaire_images:
            gestionnaire_images = GestionnaireImagesServices(self.__idmg, self.__docker)

        nom_image_docker = kwargs.get('nom') or service_name
        # image = gestionnaire_images.telecharger_image_docker(nom_image_docker)

        # Prendre un tag au hasard
        # image_tag = image.tags[0]

        configuration = self.__formatter_configuration_service(service_name)

        try:
            list_env = service_inst.attrs['Spec']['TaskTemplate']['ContainerSpec']['Env']
        except KeyError:
            list_env = configuration.get('env') or list()

        if kwargs.get('env'):
            # Ajouter toutes les variables d'environnement. Doit etre une liste format ['KEY=VAL', ...]
            list_env.extend(kwargs.get('env'))

        configuration['env'] = list_env

        # command = configuration_service.get('command')
        constraints = configuration.get('constraints')
        if constraints:
            self.__add_node_labels(constraints)

        service_inst.update(**configuration)

    def maj_services_avec_certificat(self, nom_role_certificat: str):
        nom_certificat = 'pki.%s.cert' % nom_role_certificat

        # Trouver tous les services avec le certificat
        liste_services = self.__docker.services.list()
        services_a_reconfigurer = list()
        for service in liste_services:
            try:
                container_spec = service.attrs['Spec']['TaskTemplate']['ContainerSpec']
                configs = container_spec['Configs']
                for c in configs:
                    config_name = c['ConfigName']
                    if config_name.startswith(nom_certificat):
                        services_a_reconfigurer.append(service)
            except KeyError:
                pass  # OK, pas de configs

        for s in services_a_reconfigurer:
            service_name = s.name
            self.maj_service(service_name)

    def creer_compte(self, label_cert_compte: str):
        certificat_compte = self.charger_config_recente(label_cert_compte)
        certificat_compte_pem = b64decode(certificat_compte['config'].attrs['Spec']['Data']).decode('utf-8')
        self.__service_monitor.ajouter_compte(certificat_compte_pem)

    def supprimer_service(self, service_name: str):
        filter = {'name': service_name}
        service_list = self.__docker.services.list(filters=filter)
        service_list[0].remove()

    def supprimer_container(self, container_name: str):
        filter = {'name': container_name}
        container_list = self.__docker.containers.list(filters=filter)
        container = container_list[0]
        container.stop()
        try:
            exit_code = container.wait()
            container.remove()  # Si le container ne s'est pas auto-supprime, on l'enleve
        except docker.errors.NotFound:
            # Ok, container s'est auto-supprime
            pass

    def stop_applications_modecontainer(self):
        filter = {'label': 'mode_container=true'}
        container_list = self.__docker.containers.list(filters=filter)
        for container in container_list:
            try:
                container.stop()
            except Exception:
                self.__logger.exception("Erreur stop container %s (mode application, restart requis)", container.id)

    # def activer_hebergement(self):
    #     """
    #     Active les modules d'hebergement (si pas deja fait).
    #     :return:
    #     """
    #     if not self.__hebergement_actif:
    #         # S'assurer que le repertoire d'hebergement de la MilleGrille est cree
    #         path_hebergement = os.path.join(Constantes.DEFAUT_VAR_MILLEGRILLES, self.__idmg, 'mounts/hebergement')
    #         try:
    #             os.mkdir(path_hebergement, mode=0o770)
    #         except FileExistsError:
    #             self.__logger.debug("Repertoire %s existe, ok" % path_hebergement)
    #
    #         # Ajouter modules requis
    #         modules_requis = set(self.__modules_requis)
    #         modules_requis.update(MonitorConstantes.MODULES_HEBERGEMENT)
    #         self.__modules_requis = list(modules_requis)
    #
    #         for service_name in MonitorConstantes.MODULES_HEBERGEMENT:
    #             module_config = MonitorConstantes.DICT_MODULES_PROTEGES[service_name]
    #             self.demarrer_service(service_name, **module_config)
    #
    #         self.__hebergement_actif = True
    #
    # def desactiver_hebergement(self):
    #     if self.__hebergement_actif:
    #         modules_requis = set(self.__modules_requis)
    #         modules_requis.difference_update(MonitorConstantes.MODULES_HEBERGEMENT)
    #         self.__modules_requis = list(modules_requis)
    #
    #         for service_name in MonitorConstantes.MODULES_HEBERGEMENT:
    #             try:
    #                 self.supprimer_service(service_name)
    #             except IndexError:
    #                 self.__logger.warning("Erreur retrait service %s" % service_name)
    #             self.__hebergement_actif = False

    def force_update_service(self, service_name):
        filter = {'name': service_name}
        service_list = self.__docker.services.list(filters=filter)
        try:
            service_list[0].force_update()
        except IndexError:
            self.__logger.error("Erreur force update service %s, non trouve" % service_name)

    def creer_comptes_service(self, service):
        # S'assurer que le compte MQ est cree
        container_spec = service.attrs['Spec']['TaskTemplate']['ContainerSpec']
        configs = container_spec.get('Configs')
        if configs:
            for config in configs:
                config_name = config['ConfigName']
                config_name_split = config_name.split('.')
                if len(config_name_split) >= 3 and config_name_split[0] == 'pki' and config_name_split[2] == 'cert':
                    # Commande pour creer le compte (commande idempotente)
                    self.creer_compte(config_name)

    def verifier_etat_service(self, service):
        # S'assurer que le compte MQ existe
        update_state = None
        update_status = service.attrs.get('UpdateStatus')
        if update_status is not None:
            update_state = update_status['State']
        nombre_replicas_demandes = 1

        try:
            mode_service = service.attrs['Spec']['Mode']
            nombre_replicas_demandes = mode_service['Replicated']['Replicas']
            if nombre_replicas_demandes == 0:
                # On a manuellement desactiver le service - skip
                return
        except KeyError:
            pass  # OK, pas mode replicated

        # Compter le nombre de taches actives
        running = list()

        for task in service.tasks():
            status = task['Status']
            state = status['State']
            desired_state = task['DesiredState']
            if state == 'running' or desired_state == 'running' or update_state == 'updating':
                # Le service est actif
                running.append(task)

        if len(running) < nombre_replicas_demandes:
            # Redemarrer
            self.__logger.info("Redemarrer service %s", service.name)

            # S'assurer que le compte du service existe
            task_name = service.name
            configuration_service_meta = MonitorConstantes.DICT_MODULES_PROTEGES.get(task_name)
            if configuration_service_meta:
                try:
                    configuration_service = self.charger_config_recente('docker.cfg.' + configuration_service_meta['role'])
                except KeyError:
                    self.__logger.warning("Configuration inconnue pour role : %s" % task_name)
                else:
                    config_attrs = configuration_service['config'].attrs
                    configuration_service_json = json.loads(b64decode(config_attrs['Spec']['Data']))
                    certificat_compte_cle = configuration_service_json.get('certificat_compte')
                    if certificat_compte_cle:
                        self.creer_compte(certificat_compte_cle)

            service.force_update()

    def charger_config(self, config_name):
        filtre = {'name': config_name}
        configs = self.__docker.configs.list(filters=filtre)
        return b64decode(configs[0].attrs['Spec']['Data'])

    def charger_configs(self, config_name):
        """
        Retourne une liste de configurations
        :param config_name:
        :return:
        """
        filtre = {'name': config_name}
        configs = self.__docker.configs.list(filters=filtre)

        config_list = list()
        for config in configs:
            configdict = b64decode(config.attrs['Spec']['Data'])
            config_list.append({'name': config.name, 'configuration': configdict})

        return config_list

    def sauvegarder_secret(self, secret_name: str, data: bytes, ajouter_date=False, labels: dict = None):
        date_courante = None
        if ajouter_date:
            date_courante = datetime.datetime.utcnow().strftime(MonitorConstantes.DOCKER_LABEL_TIME)
            secret_name = secret_name + '.' + date_courante

        labels_secret = {'idmg': self.__idmg}
        if labels is not None:
            labels_secret.update(labels)

        self.__docker.secrets.create(name=secret_name, data=data, labels=labels_secret)

        if self.__insecure:
            # Sauvegarder le secret sur disque
            path_secret = path.join(self.__secrets, secret_name)
            with open(path_secret, 'wb') as fichier:
                fichier.write(data)

        return secret_name, date_courante

    def sauvegarder_config(self, config_name, data, labels: dict = None):
        filtre = {'name': config_name}
        configs = self.__docker.configs
        config_existante = configs.list(filters=filtre)
        if len(config_existante) > 0:
            for conf in config_existante:
                if conf.name == config_name:
                    conf.remove()

        labels_config = {'idmg': self.__idmg}
        if labels is not None:
            labels_config.update(labels)

        if isinstance(data, dict):
            data_string = json.dumps(data).encode('utf-8')
        elif isinstance(data, str):
            data_string = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_string = data
        else:
            raise ValueError("Type data non supporte")
        configs.create(name=config_name, data=data_string, labels=labels_config)

    def supprimer_config(self, config_name):
        filtre = {'name': config_name}
        configs = self.__docker.configs
        config_existante = configs.list(filters=filtre)
        if len(config_existante) == 1:
            config_existante[0].remove()

    def supprimer_secret(self, config_name):
        filtre = {'name': config_name}
        secrets = self.__docker.secrets
        secret_existant = secrets.list(filters=filtre)
        if len(secret_existant) == 1:
            secret_existant[0].remove()

    def charger_config_recente(self, config_name):
        return self.__trouver_config(config_name)

    def trouver_config(self, config_name):
        return self.__trouver_config(config_name)

    def __trouver_config(self, config_name):
        try:
            return MonitorConstantes.trouver_config(config_name, self.__docker)
        except AttributeError as ae:
            self.__logger.warning("Configuration %s non trouvee" % config_name)
            raise ae

    def trouver_secret(self, secret_name):
        secret_names = secret_name.split(';')
        secrets = None
        for secret_name_val in secret_names:
            # Utiliser mode docker
            filtre = {'name': secret_name_val}
            secrets = self.__docker.secrets.list(filters=filtre)
            if len(secrets) > 0:
                break

        if len(secrets) == 0:
            raise PkiCleNonTrouvee("Secret non trouve : %s" % secret_name)

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
            date_secret = None
            config_secret = None
            for key, value in date_secrets.items():
                if config_name in key.split(';'):
                    if date_secret is None or int(date_secret) < int(value):
                        nom_filtre = secret_name + '.' + value
                        filtre = {'name': nom_filtre}
                        secrets = self.__docker.secrets.list(filters=filtre)
                        try:
                            config_secret = secrets[0]
                            date_secret = value
                        except IndexError:
                            pass

            if config_secret is not None:
                return {
                    'secret_id': config_secret.attrs['ID'],
                    'secret_name': config_secret.name,
                    'date': date_secret,
                }

        raise ValueError("Aucun secrets %s ne correspond a une config" % str(secret_names))

    def __trouver_secret_regex(self, secret_params: dict) -> list:
        regex_pattern = secret_params['name']
        output_name = secret_params['filename']
        secrets = self.__docker.secrets.list()

        p = re.compile(regex_pattern)
        mappings = list()
        for secret in secrets:
            secret_name = secret.name
            r = p.match(secret_name)
            if r is not None:

                output_name_update = output_name
                groups = r.groups()
                for i in range(0, len(groups)):
                    g = groups[i]
                    index = i+1
                    output_name_update = output_name_update.replace('$%d' % index, g)

                mapping = {
                    'secret_id': secret.attrs['ID'],
                    'secret_name': secret.name,
                    'filename': output_name_update
                }
                mappings.append(mapping)

        if len(mappings) == 0:
            raise ValueError("Le regex ne correspond a aucun secret : %s" % regex_pattern)

        return mappings

    def __mapping(self, valeur: str):
        for cle, valeur_mappee in self.__mappings.items():
            cle = cle.upper()
            valeur = valeur.replace('${%s}' % cle, str(valeur_mappee))

        return valeur

    def __formatter_configuration_service(self, service_name, **kwargs):
        config_service = json.loads(self.charger_config('docker.cfg.' + service_name))
        self.__logger.debug("Configuration service %s : %s", service_name, str(config_service))

        dict_config_docker = self.__remplacer_variables(service_name, config_service, **kwargs)

        return dict_config_docker

    def __formatter_configuration_container(self, container_name, config: dict = None, **kwargs):
        config_container = config or json.loads(self.charger_config('docker.cfg.' + container_name))
        self.__logger.debug("Configuration container %s : %s", container_name, str(config_container))

        dict_config_docker = self.__remplacer_variables(container_name, config_container, mode_container=True)

        dict_config_docker['detach'] = True
        # dict_config_docker['auto_remove'] = True
        labels = dict_config_docker.get('labels')
        if not labels:
            labels = dict()
            dict_config_docker['labels'] = labels

        # Injecter le mount avec les secrets
        mounts = dict_config_docker.get('mounts')
        if not mounts:
            mounts = list()
            dict_config_docker['mounts'] = mounts

        # if self.__service_monitor.is_dev_mode:
        #     # On est en mode developpment, utiliser /var/opt/millegrilles_secrets
        #     self.__logger.debug("Configuration container : Path secret externe : %s" % MonitorConstantes.PATH_SOURCE_SECRET_DEFAUT)
        #     mounts.append({
        #         'target': MonitorConstantes.PATH_SECRET_DEFAUT,
        #         'source': MonitorConstantes.PATH_SOURCE_SECRET_DEFAUT,
        #         'type': 'bind'
        #     })
        # else:
        #     self.__logger.debug("Configuration container : Path secret volume interne millegrille-secrets")
        #     mounts.append({
        #         'target': MonitorConstantes.PATH_SECRET_DEFAUT,
        #         'source': 'millegrille-secrets',
        #         'type': 'volume'
        #     })

        path_certificat = kwargs.get('certificat_volume')
        if path_certificat is not None:
            path_secret_docker = path.join(MonitorConstantes.PATH_SOURCE_SECRET_DEFAUT, container_name)
            os.makedirs(path_secret_docker, mode=0o755, exist_ok=True)
            mounts.append({
                'target': path_certificat or MonitorConstantes.PATH_SECRET_DEFAUT,
                'source': path.join(MonitorConstantes.PATH_SOURCE_SECRET_DEFAUT, container_name),
                'type': 'bind'
            })

        nom_certificat = kwargs.get('certificat_compte')
        if nom_certificat is not None:
            self.__regenerer_certificat_container(container_name, nom_certificat)

        labels['mode_container'] = 'true'
        labels['application'] = kwargs['application']

        return dict_config_docker

    def __regenerer_certificat_container(self, container_name: str, nom_certificat: str):
        # nom_certificat = config_image.get('certificat_compte')
        nom_role = nom_certificat.split('.')[1]
        path_secret_docker = path.join(MonitorConstantes.PATH_SOURCE_SECRET_DEFAUT, container_name)
        os.makedirs(path_secret_docker, mode=0o755, exist_ok=True)

        clecert = self.__service_monitor.gestionnaire_certificats.generer_clecert_module(nom_role, self.__service_monitor.noeud_id)
        secret_pem_bytes = clecert.private_key_bytes
        chaine = clecert.chaine
        ca_cert = clecert.ca

        with open(path.join(path_secret_docker, 'cert.pem'), 'w') as fichier:
            fichier.write(''.join(chaine))
        with open(path.join(path_secret_docker, 'key.pem'), 'wb') as fichier:
            fichier.write(secret_pem_bytes)
        with open(path.join(path_secret_docker, 'millegrille.cert.pem'), 'w') as fichier:
            fichier.write(ca_cert)

    def __remplacer_variables(self, nom_service, config_service, mode_container=False, **kwargs):
        self.__logger.debug("Remplacer variables %s" % nom_service)
        dict_config_docker = dict()

        try:
            # Name
            dict_config_docker['name'] = config_service['name']

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
                if mode_container:
                    dict_config_docker['restart_policy'] = config_restart_policy
                else:
                    dict_config_docker['restart_policy'] = RestartPolicy(**config_restart_policy)

            # Service Mode
            config_service_mode = config_service.get('mode')
            if config_service_mode:
                dict_config_docker['mode'] = ServiceMode(**config_service_mode)

            # Variables d'environnement, inclus mapping
            # Ne pas ajouter pour le mode container (plutot utiliser 'environment')
            nom_elem_environment = 'env'
            if mode_container:
                nom_elem_environment = 'environment'

            config_env = config_service.get(nom_elem_environment)
            config_env_dict = dict()
            if config_env:
                # Convertir liste en dict, mapping des variables
                for items in config_env:
                    elems = items.split('=')
                    valeur = self.__mapping("=".join(elems[1:]))
                    config_env_dict[elems[0]] = valeur

            # config_env = [self.__mapping(valeur) for valeur in config_env]

            connexion_mq = self.__service_monitor.get_info_connexion_mq(nowait=True)
            for key, value in connexion_mq.items():
                # config_env.append(key + "=" + str(value))
                config_env_dict[key] = str(value)

            # Toujours ajouter l'id du noeud, le IDMG, MQ connexion params
            # config_env.append("MG_NOEUD_ID=" + self.__service_monitor.noeud_id)
            # config_env.append("MG_IDMG=" + self.__service_monitor.idmg)
            config_env_dict["MG_NOEUD_ID"] = self.__service_monitor.noeud_id
            config_env_dict["MG_IDMG"] = self.__service_monitor.idmg

            # Reconvertir env en liste
            # config_env_list = list()
            # for items in config_env_dict.items():
            #     config_env_list.append(items[0] + '=' + items[1])
            config_env_list = ['='.join(i) for i in config_env_dict.items()]

            dict_config_docker[nom_elem_environment] = config_env_list

            # Constraints
            config_constraints = config_service.get('constraints')
            if config_constraints:
                dict_config_docker['constraints'] = config_constraints

            # Service labels
            config_labels = config_service.get('labels')
            updated_labels = dict()
            dict_config_docker['labels'] = updated_labels

            if config_labels:
                for key, value in config_labels.items():
                    value = self.__mapping(value)
                    updated_labels[key] = value

            if kwargs.get('application'):
                updated_labels['application'] = kwargs.get('application')
                if config_service.get('certificat_compte'):
                    updated_labels['certificat'] = 'true'
                    updated_labels['certificat_nom'] = config_service['certificat_compte']
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

            hosts = config_service.get('hosts')
            if hosts is not None:
                mapped_hosts = dict()
                for key, value in hosts.items():
                    updated_value = self.__mapping(value)
                    mapped_hosts[key] = updated_value
                dict_config_docker['hosts'] = mapped_hosts

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

                        date_config = config_dict.get('date')
                        if date_config:
                            dates_configs[config_name] = date_config
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
                    if secret.get('regex'):
                        references = self.__trouver_secret_regex(secret)
                        for secret_reference in references:
                            # secret_reference['filename'] = secret['filename']
                            secret_reference['uid'] = secret.get('uid') or 0
                            secret_reference['gid'] = secret.get('gid') or 0
                            secret_reference['mode'] = secret.get('mode') or 0o444
                            liste_secrets.append(SecretReference(**secret_reference))
                    else:
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
                if not mode_container:
                    dict_config_docker['mounts'] = [self.__mapping(mount) for mount in config_mounts]
                else:
                    self.__logger.warning("Mounts : Format des containers, ignorer pour l'instant")
                    mounts = list()
                    for mount in config_mounts:
                        mount_obj = Mount(mount['target'], mount['source'], mount['type'])
                        mounts.append(mount_obj)
                    dict_config_docker['mounts'] = mounts

            devices = config_service.get('devices')
            if devices:
                dict_config_docker['devices'] = devices

            privileged = config_service.get('privileged')
            if privileged:
                dict_config_docker['privileged'] = True

            network = config_service.get('network')
            if devices:
                dict_config_docker['network'] = network

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

    def trouver_container_pour_service(self, nom_service):
        containers_service = self.__docker.containers.list(filters={'name': nom_service})
        container_trouve = containers_service[0]
        return container_trouve.id

    def trouver_application(self, nom_application):
        containers = self.__docker.containers.list(all=True, filters={'label': 'application=' + nom_application})
        services = self.__docker.services.list(filters={'label': 'application=' + nom_application})

        resultat = {
            'containers': containers,
            'services': services,
        }

        return resultat

    def executer_scripts(self, container_id: str, commande: str, tar_path: str = None, environment: list = None):
        container = self.__docker.containers.get(container_id)

        if tar_path:
            # On copie l'archive tar et extrait dans le container
            with open(tar_path, 'rb') as fichier:
                container.put_archive('/tmp', fichier)
                os.remove(tar_path)  # Cleanup fichier temporaire

        exit_code, output = container.exec_run(commande, stream=True, environment=environment)
        output_result = None
        for gen_output in output:
            for line in gen_output.decode('utf-8').split('\n'):
                self.__logger.info("Script output : %s" % line)
                if line and line != '\n':
                    output_result = line

        # La dernier ligne devrait etre le resultat avec code exit, en json
        if output_result:
            try:
                resultat = json.loads(output_result)
                if resultat.get('exit') != 0:
                    raise ExceptionExecution(
                        "Erreur demarrage application, exit : %d" % resultat.get('exit'),
                        resultat=resultat
                    )
            except json.decoder.JSONDecodeError:
                raise ExceptionExecution(
                    "Erreur output, format n'est pas JSON, exit",
                    resultat=output_result
                )

    def executer_script_blind(self, container_id: str, commande: str, environment: list = None):
        container = self.__docker.containers.get(container_id)
        exit_code, output = container.exec_run(commande, stream=False, environment=environment)
        return exit_code, output

    def put_archives(self, container_id: str, src_path: str, dst_path: str):
        container = self.__docker.containers.get(container_id)

        with open(src_path, 'rb') as fichier:
            container.put_archive(dst_path, fichier)

    def save_archives(self, container_id: str, src_path: str,
                      dest_path: str = '/tmp/monitorbackup',
                      dest_prefix: str = 'backup') -> str:
        """
        Recupere un fichier a partir d'un container docker.
        :param container_id:
        :param src_path:
        :param dest_path:
        :param dest_prefix:
        :return: Liste des fichiers extraits
        """
        container = self.__docker.containers.get(container_id)

        os.makedirs(dest_path, exist_ok=True)

        archive_index = 0
        archive_name = '%s.%d.tar' % (dest_prefix, archive_index)
        path_archive_backup = os.path.join(dest_path, archive_name)
        tar_data, stat_data = container.get_archive(src_path)

        with open(path_archive_backup, 'wb') as output:
            for chunk in tar_data:
                output.write(chunk)

        return path_archive_backup

    def get_archive_bytes(self, container_id, src_path) -> bytes:
        container = self.__docker.containers.get(container_id)
        tar_data, stat_data = container.get_archive(src_path)
        array_data = bytes()
        for chunk in tar_data:
            array_data = array_data + chunk
        return array_data

    def get_service(self, nom_service):
        services = self.__docker.services.list(filters={'name': nom_service})
        return services[0]

    def get_application_certificats(self):
        services = self.__docker.services.list(filters={'label': "certificat=true"})
        return services

    def get_liste_services(self):
        services = self.__docker.services.list()

        # Mapper services et etat
        dict_services = dict()
        for service in services:
            attrs = service.attrs
            spec = attrs['Spec']
            info_service = {
                'creation_service': service.attrs['CreatedAt'],
                'maj_service': service.attrs['UpdatedAt'],
            }
            labels = spec.get('Labels')
            if labels:
                info_service['labels'] = labels
            mode = spec.get('Mode')
            if mode:
                replicated = mode.get('Replicated')
                if replicated:
                    replicas = replicated.get('Replicas')
                    if replicas:
                        info_service['replicas'] = replicas

            tasks = [task for task in service.tasks() if task['DesiredState'] == 'running']
            if len(tasks) > 0:
                task = tasks[-1]
                info_service['etat'] = task['Status']['State']
                info_service['message_tache'] = task['Status']['Message']

            dict_services[service.name] = info_service

        return dict_services

    def get_liste_containers(self):
        containers = self.__docker.containers.list(all=True)

        # Mapper services et etat
        dict_containers = dict()
        for container in containers:
            attrs = container.attrs
            info_container = {
                'creation': attrs['Created'],
                'restart_count': attrs['RestartCount'],
            }

            state = attrs['State']
            info_container['etat'] = state['Status']
            info_container['running'] = state['Running']
            info_container['dead'] = state['Dead']
            info_container['finished_at'] = state['FinishedAt']

            info_container['labels'] = attrs['Config']['Labels']

            dict_containers[attrs['Name']] = info_container

        return dict_containers

    def get_nginx_onionize_hostname(self) -> Optional[str]:
        """
        Retourne le hostname .onion (TOR) du service nginx si disponible
        """
        filtre = {'name': 'onionize'}
        list_containers = self.docker_client.containers.list(filters=filtre)
        try:
            container = list_containers[0]
            resultat = container.exec_run('cat /var/lib/tor/onion_services/nginx/hostname')
            hostname = resultat.output.decode('utf-8').strip()
            return hostname
        except IndexError:
            pass

    @property
    def idmg(self):
        return self.__idmg

    @idmg.setter
    def idmg(self, idmg):
        self.__idmg = idmg

    @property
    def idmg_tronque(self):
        return self.__idmg[0:12]

    @property
    def nodename(self):
        nodename = self.__docker.info()['Name']
        return nodename

    @property
    def hostname(self):
        fqdn = os.getenv('HOSTNAME_MONITOR')
        if not fqdn:
            # Tenter de charger le domaine configure avec acme pour correspondre au certificat public
            try:
                config_acme = self.charger_config('acme.configuration')
                config_dict = json.loads(config_acme.decode('utf-8'))
                fqdn = config_dict['domain']
            except IndexError as e:
                # On n'a pas de configuration publique (infrastructure), on retourne le nom local du serveur
                fqdn = socket.gethostbyaddr(socket.gethostname())[0]
        return fqdn

    @staticmethod
    def get_local_ips():
        local_ips = IpUtils.get_local_ips()
        return local_ips

    def get_configuration_services(self):
        return self.__configuration_services

    @property
    def docker_client(self):
        return self.__docker


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

    def telecharger_image_docker(self, nom_service, **kwargs):
        """
        S'assure d'avoir une version locale de chaque image - telecharge au besoin
        :return:
        """
        images_non_trouvees = list()

        self.charger_versions()

        # Il est possible de definir des registre specifiquement pour un service
        image = self.pull_image(nom_service, images_non_trouvees, **kwargs)

        if len(images_non_trouvees) > 0:
            message = "Images non trouvees: %s" % str(images_non_trouvees)
            raise Exception(message)

        return image

    def pull_image(self, service, images_non_trouvees, **kwargs):
        registries = self._versions_images.get('registries')
        images_info = self._versions_images['images']
        config = images_info[service]
        nom_image = config['image']
        tag = config['version'] or kwargs.get('tag')

        service_registries = config.get('registries')
        if service_registries is None:
            service_registries = registries
        image_locale = self.get_image_locale(nom_image, tag)
        if image_locale is None and kwargs.get('no_pull') is not True:
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

        if image_locale is None:
            images_non_trouvees.append('%s:%s' % (image_locale, tag))

        return image_locale

    def pull(self, image_name, tag):
        """
        Effectue le telechargement d'une image.
        Cherche dans tous les registres configures.
        """

        image = None
        try:
            image = self.get_image_locale(image_name, tag)
            if image is None:
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

    def get_image(self, registry: str, tag: str):
        """
        Simple get/pull image.
        :param registry:
        :param tag:
        :return:
        """
        try:
            return self._docker.images.get(registry + ':' + tag)
        except APIError as apie:
            # if apie.status_code == 404:
            #     return self._docker.images.pull(registry, tag)
            raise apie


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


class DummySecret:

    def __init__(self, nom_secret):
        self.name = nom_secret
        self.attrs = {'ID': nom_secret}

# Gestionnaire d'applications privees
import logging
import docker
import json
import secrets
import tarfile
import io

from typing import Optional
from threading import Event
from typing import cast
from base64 import b64encode, b64decode
from os import path, makedirs
from docker.errors import APIError
from docker.types import SecretReference, RestartPolicy, ConfigReference, Mount

from millegrilles import Constantes
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker, GestionnaireImagesDocker, \
    GestionnaireImagesServices
from millegrilles.monitor.MonitorConstantes import CommandeMonitor, ExceptionExecution, PkiCleNonTrouvee
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat
from millegrilles.dao.MessageDAO import TraitementMQRequetesBlocking


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
        self.__wait_start_container_name = None
        self.__wait_start_service_container_id = None

        self.__wait_die_service_container_id = None
        self.__wait_event_die = Event()

        self.__handler_requetes: [TraitementMQRequetesBlocking] = None

        self.__scripts_volume = '/var/opt/millegrilles/scripts'  # mg_scripts  # Scripts geres pas monitor
        self.__backup_volume = '/var/opt/millegrilles/consignation/backup_app_work'  # Rep backup app

    def event(self, event):
        self.__logger.debug("Event docker APPS : %s", str(event))
        event_json = json.loads(event.decode('utf-8'))

        type = event_json.get('Type')
        action = event_json.get('Action')
        status = event_json.get('status')
        if type is not None and action is not None:
            action = 'docker/' + type
            # Retirer timeNano, nombre long cause des problemes de parsing en javascript
            try:
                del event_json['timeNano']
            except KeyError:
                pass # Pas de timeNano
            self.__service_monitor.emettre_evenement(action, event_json)

        if self.__wait_die_service_container_id is not None and status == 'die':
            try:
                service_id = event_json['Actor']['Attributes']['com.docker.swarm.service.id']
                if self.__wait_die_service_container_id == service_id:
                    self.__wait_event_die.set()
            except KeyError:
                pass

        if self.__wait_start_service_name or self.__wait_start_container_name:
            # Verifier si le container correspond au service
            if event_json.get('Type') == 'container' and event_json.get('status') == 'start' and event_json.get('Action') == 'start':
                actor = event_json.get('Actor')
                if actor:
                    attributes = actor.get('Attributes')
                    if attributes:
                        service_name = attributes.get('com.docker.swarm.service.name')
                        if service_name and service_name == self.__wait_start_service_name:
                            self.__logger.debug("Service %s demarre" % service_name)
                            self.__wait_start_service_container_id = event_json['id']
                            self.__wait_container_event.set()
                        container_name = attributes.get('name')
                        if container_name and container_name == self.__wait_start_container_name:
                            self.__logger.debug("Container %s demarre" % container_name)
                            self.__wait_start_service_container_id = event_json['id']
                            self.__wait_container_event.set()

    def installer_application(self, commande: CommandeMonitor):
        self.__logger.info("Installation application %s", str(commande))

        mq_properties = commande.mq_properties
        reply_to = mq_properties.reply_to
        correlation_id = mq_properties.correlation_id
        reponse = {'ok': True}

        nom_application = commande.contenu['nom_application']
        try:
            configuration_docker = commande.contenu['configuration']

            if configuration_docker is None:
                # Tenter de charger la configuration existante
                configuration_existante = self.__gestionnaire_modules_docker.charger_config('app.cfg.' + nom_application)
                configuration_docker = json.loads(configuration_existante.decode('utf-8'))
                commande.contenu['configuration'] = configuration_docker
                commande.contenu['configuration_courante'] = True

            self.__service_monitor.generateur_transactions.transmettre_reponse(
                reponse, replying_to=reply_to, correlation_id=correlation_id)

            self.preparer_installation(nom_application, configuration_docker)

            # Transmettre maj
            self.__service_monitor.emettre_presence()
        except Exception as e:
            self.__logger.exception("Erreur installation application")
            reponse['ok'] = False
            reponse['err'] = str(e)
            self.__service_monitor.generateur_transactions.transmettre_reponse(
                reponse, replying_to=reply_to, correlation_id=correlation_id)
        finally:
            # Nettoyer les volumes docker transitifs potentiellement crees
            docker_client = self.__gestionnaire_modules_docker.docker_client
            volumes = ['scripts', 'backup']
            for vol in volumes:
                try:
                    volume = docker_client.volumes.get(vol + '_' + nom_application)
                    volume.remove()
                except APIError as apie:
                    if apie.status_code != 404:
                        self.__logger.exception("Erreur nettoyage volume %s pour application %s" % (vol, nom_application))

    def configurer_application(self, commande: CommandeMonitor):
        nom_app = commande.contenu['nom_application']
        nom_configuration = 'app.cfg.' + nom_app
        configuration = commande.contenu['configuration']

        # Changer configuration existante
        configuration_precendente = self.__gestionnaire_modules_docker.charger_config(nom_configuration)
        self.__gestionnaire_modules_docker.supprimer_config(nom_configuration)
        self.__gestionnaire_modules_docker.sauvegarder_config(nom_configuration, configuration)

        return {'ok': True}

    def commande_demarrer_application(self, commande: CommandeMonitor):
        self.__logger.info("Demarrer application %s", str(commande))

        mq_properties = commande.mq_properties
        reply_to = mq_properties.reply_to
        correlation_id = mq_properties.correlation_id
        reponse = {'ok': True}
        nom_application = commande.contenu['nom_application']

        try:
            # Tenter de charger la configuration existante
            configuration_existante = self.__gestionnaire_modules_docker.charger_config(
                'app.cfg.' + nom_application)
            configuration_docker = json.loads(configuration_existante.decode('utf-8'))
            commande.contenu['configuration'] = configuration_docker
            commande.contenu['configuration_courante'] = True

            self.__service_monitor.generateur_transactions.transmettre_reponse(
                reponse, replying_to=reply_to, correlation_id=correlation_id)

            self.preparer_installation(nom_application, configuration_docker)

            # Transmettre maj
            self.__service_monitor.emettre_presence()
        except Exception as e:
            self.__logger.exception("Erreur demarrer application")
            reponse['ok'] = False
            reponse['err'] = str(e)
            self.__service_monitor.generateur_transactions.transmettre_reponse(
                reponse, replying_to=reply_to, correlation_id=correlation_id)

    def supprimer_application(self, commande: CommandeMonitor):
        self.__logger.info("Supprimer application %s", str(commande))

        nom_application = commande.contenu['nom_application']
        self.effectuer_desinstallation(nom_application)

        # Transmettre maj
        self.__service_monitor.emettre_presence()

        return {'ok': True}

    def backup_application(self, commande: CommandeMonitor):
        self.__logger.info("Backup application %s", str(commande))

        reponse_info = dict()
        try:
            applications = list()
            # Transmettre reponse pour indiquer commande recue
            mq_properties = commande.mq_properties
            if mq_properties is not None:
                reply_to = mq_properties.reply_to
                correlation_id = mq_properties.correlation_id
                reponse = {'ok': True}
                self.__service_monitor.generateur_transactions.transmettre_reponse(
                    reponse, replying_to=reply_to, correlation_id=correlation_id)

            try:
                nom_image_docker = commande.contenu['nom_application']
                configuration_docker = commande.contenu.get('configuration')
                applications.append({'nom_application': nom_image_docker, 'configuration': configuration_docker})
            except KeyError:
                # On n'a pas d'application en particulier, lancer le backup de toutes les applications
                applications = self.trouver_applications_backup(commande.contenu)

            try:
                self.lancer_backup_applications(applications)
                reponse_info['ok'] = True
            except Exception as e:
                reponse_info['ok'] = False
                reponse_info['err'] = str(e)

            self.transmettre_evenement_backup(
                'global',
                Constantes.ConstantesBackup.EVENEMENT_BACKUP_APPLICATIONS_TERMINE,
                type_event=Constantes.ConstantesBackup.EVENEMENT_RESTAURATION_APPLICATION,
                info=reponse_info)

        except Exception as e:
            reponse_info['ok'] = False
            reponse_info['err'] = str(e)

            self.transmettre_evenement_backup(
                'global',
                Constantes.ConstantesBackup.EVENEMENT_BACKUP_APPLICATIONS_TERMINE,
                type_event=Constantes.ConstantesBackup.EVENEMENT_RESTAURATION_APPLICATION,
                info=reponse_info)

    def copier_volume_vers_backup(self, nom_application, volumes: list, path_backup='/var/opt/millegrilles/consignation/backup_app_work'):
        # nom_application = 'redmine_mariadb'

        # volumes = ['redmine_files']
        mounts = list()

        # Mount /bakcup,
        mounts.append(Mount(type='bind', source=path.join(path_backup, nom_application), target='/backup'))
        cmd = ''
        for v in volumes:
            path_target = path.join('/', v)
            m = Mount(type='volume', target=path_target, source=v, read_only=True)
            mounts.append(m)

            # Creer liste de commandes de copie des fichiers de volumes vers /backup
            cmd = cmd + 'cp -ru %s /backup; ' % path_target

        docker_client = self.__gestionnaire_modules_docker.docker_client
        docker_client.containers.run('alpine', cmd, auto_remove=True, mounts=mounts, name='docker_volume_copy')

    def restore_application(self, commande: CommandeMonitor):
        self.__logger.info("Restore application %s", str(commande))

        reponse_info = dict()
        try:
            # Transmettre reponse pour indiquer commande recue
            mq_properties = commande.mq_properties
            reply_to = mq_properties.reply_to
            correlation_id = mq_properties.correlation_id
            reponse = {'ok': True}
            self.__service_monitor.generateur_transactions.transmettre_reponse(
                reponse, replying_to=reply_to, correlation_id=correlation_id)

            applications = self.trouver_applications_backup(commande.contenu)
            nom_application = commande.contenu['nom_application']
            nom_config_app = 'app.cfg.' + nom_application
            configuration_docker = [a for a in applications if a['name'] == nom_config_app][0]

            self.effectuer_restauration(nom_application, configuration_docker)
            reponse_info['ok'] = True

        except Exception as e:
            self.__logger.exception("Erreur demarrage application")
            reponse_info['err'] = str(e)

        self.transmettre_evenement_backup(
            commande.contenu['nom_application'],
            Constantes.ConstantesBackup.EVENEMENT_RESTAURATION_TERMINEE,
            type_event=Constantes.ConstantesBackup.EVENEMENT_RESTAURATION_APPLICATION,
            info=reponse_info
        )

    def charger_dependances_restauration(self, configuration_docker):
        """
        Chargement recursif de toutes les configuration docker associees a une application
        :param configuration_docker:
        :return: Liste de toutes les configurations incluant dependances
        """
        liste_configuration = list()
        # Restaurer toutes les dependances de l'application
        for config_image in configuration_docker['dependances']:
            if config_image.get('dependances'):
                # Recursif
                liste = self.charger_dependances_restauration(config_image)
                liste_configuration.extend(liste)
            elif config_image.get('image'):
                liste_configuration.append(config_image)

        return liste_configuration

    def preparer_installation(self, nom_application, configuration_docker, **kwargs):
        """
        Installe une nouvelle application.
        :param nom_application:
        :param configuration_docker:
        :param tar_scripts:
        :param kwargs:
        :return:
        """
        gestionnaire_images_applications = GestionnaireImagesApplications(
            self.__service_monitor.idmg, self.__service_monitor.docker)
        gestionnaire_images_applications.set_configuration(configuration_docker)

        config_name = 'app.cfg.' + nom_application

        if configuration_docker.get('configuration_courante') is not True:
            self.__gestionnaire_modules_docker.sauvegarder_config(config_name, configuration_docker)

        # Verifier si on a des scripts d'installation
        try:
            # Copier les scripts dans le sous-repertoire approprie
            server_file_obj = io.BytesIO(b64decode(configuration_docker['scripts']))
        except KeyError:
            pass  # OK
        else:
            path_scripts_app = path.join(self.__scripts_volume, nom_application)
            makedirs(path_scripts_app, mode=0o755, exist_ok=True)
            tar_content = tarfile.open(fileobj=server_file_obj)
            tar_content.extractall(path_scripts_app)

        # Installer toutes les dependances de l'application en ordre
        for config_image in configuration_docker['dependances']:
            try:
                self.installer_dependance(gestionnaire_images_applications, configuration_docker, config_image, nom_application)
            except APIError as api:
                if api.status_code == 409 and kwargs.get('shared'):
                    pass  # OK
                else:
                    raise api

        nginx_config = configuration_docker.get('nginx')
        if nginx_config is not None:
            path_location = nginx_config.get('path_location')
            conf_location = nginx_config.get('conf_location')
            server_file = nginx_config.get('server_file')
            if path_location is not None or conf_location is not None:
                elems_config = nginx_config.copy()
                elems_config['appname'] = nom_application
                if conf_location is not None:
                    # Utiliser configuration custom
                    server_file_obj = io.BytesIO(b64decode(configuration_docker['scripts']))
                    tar_content = tarfile.open(fileobj=server_file_obj)
                    conf_file_member = tar_content.getmember(conf_location)
                    conf = tar_content.extractfile(conf_file_member).read().decode('utf-8')
                else:
                    conf = """
                        location {path_location} {{
                            set $upstream_{appname} {proxypass};
                            proxy_pass $upstream_{appname};
                            include /etc/nginx/conf.d/component_base_auth.include;
                        }}
                    """
                conf = conf.format(**elems_config)

                # Injecter le fichier dans le repertoire de nginx
                path_nginx = '/var/opt/millegrilles/nginx/modules'
                with open(path.join(path_nginx, nom_application + '.app.location'), 'w') as fichier:
                    fichier.write(conf)

            elif server_file is not None:
                conf: Optional[str] = None
                # Charger le fichier a partir de l'archive tar
                server_file_obj = io.BytesIO(b64decode(configuration_docker['scripts']))
                tar_content = tarfile.open(fileobj=server_file_obj)
                conf_file_member = tar_content.getmember(server_file)
                conf = tar_content.extractfile(conf_file_member).read().decode('utf-8')

                server_file_obj = None
                tar_content = None

                # Remplacer les variables de conf
                server_domain = self.__gestionnaire_modules_docker.hostname
                app_domain = '.'.join([nginx_config['subdomain'], server_domain])

                conf = conf.replace("${HOSTNAME}", server_domain)
                conf = conf.replace("${APP_DOMAIN}", app_domain)

                if nginx_config.get('params'):
                    for key, value in nginx_config['params'].items():
                        conf = conf.replace('${%s}' % key, value)

                # Injecter le fichier dans le repertoire de nginx
                path_nginx = '/var/opt/millegrilles/nginx/modules'
                with open(path.join(path_nginx, nom_application + '.app.server'), 'w') as fichier:
                    fichier.write(conf)

            # Redemarrer nginx
            nom_service_nginx = 'nginx'
            self.__gestionnaire_modules_docker.force_update_service(nom_service_nginx)

    def installer_dependance(self, gestionnaire_images_applications, config_docker, config_image, nom_application):
        nom_container_docker = config_image['config']['name']
        config_name = 'docker.cfg.' + nom_container_docker
        config_elem = config_image['config']
        self.__gestionnaire_modules_docker.sauvegarder_config(config_name, config_elem, {'application': nom_application})

        # Generer valeurs au besoin
        self.generer_motsdepasse(config_image)

        try:
            self.demarrer_application(config_elem, config_image, gestionnaire_images_applications, nom_container_docker, nom_application)
        except PkiCleNonTrouvee:
            # La cle n'a pas ete trouvee, tenter de generer la cle/certificat et reessayer
            self.__service_monitor.regenerer_certificat(
                ConstantesGenerateurCertificat.ROLE_APPLICATION_PRIVEE,
                nom_container_docker,
                nomcle=nom_container_docker or config_elem['name']
            )
            self.demarrer_application(config_elem, config_image, gestionnaire_images_applications, nom_container_docker, nom_application)

        config_installation = config_image.get('installation')
        if config_installation:
            try:
                scripts_post_start = config_installation['post_start']
                for script in scripts_post_start:
                    try:
                        configuration_script = config_docker['installation'][script]
                        self.__logger.info(
                            "Executer script d'installation du container id : %s" % self.__wait_start_service_container_id)
                    except KeyError:
                        continue  # Aucun script

                    # Les scripts ont eta installes dans le volume scripts_[appname] qui est inclus dans le service
                    # self.__gestionnaire_modules_docker.executer_scripts(
                    #     self.__wait_start_service_container_id, config_installation['commande'], tar_scripts)
                    commande = configuration_script['command']

                    image_info = config_docker['images'][configuration_script['image']]

                    self._executer_service(nom_application, configuration_script, commande, image_info)
            except ExceptionExecution as ex:
                codes_ok = config_installation.get('exit_codes_ok')
                if not codes_ok or ex.resultat['exit'] not in codes_ok:
                    raise ex

        if config_image.get('etape_seulement'):
            # C'est un service intermediaire pour l'installation/backup
            # On supprime le service maintenant que la tache est terminee
            self.__gestionnaire_modules_docker.supprimer_service(config_elem['name'])

    def generer_motsdepasse(self, config_image):
        valeurs_a_generer = config_image.get('generer')
        mots_de_passe = dict()
        if valeurs_a_generer:
            liste_motsdepasse = valeurs_a_generer.get('motsdepasse')
            for motdepasse_config in liste_motsdepasse:
                label_motdepasse = motdepasse_config['name']

                # Verifier si le mot de passe existe deja
                try:
                    secret_passwd = self.__gestionnaire_modules_docker.trouver_secret(motdepasse_config['name'])
                except PkiCleNonTrouvee:
                    # Generer le mot de passe
                    motdepasse = b64encode(secrets.token_bytes(16))
                    # Conserver mot de passe en memoire pour generer script, au besoin
                    mots_de_passe[label_motdepasse] = motdepasse.decode('utf-8')
                    labels = {'mg_type': 'password'}
                    self.__gestionnaire_modules_docker.sauvegarder_secret(label_motdepasse, motdepasse,
                                                                          ajouter_date=True, labels=labels)

    def demarrer_application(self, config_elem, config_image, gestionnaire_images_applications, nom_container_docker, nom_application):
        # Preparer le demarrage du service, intercepter le demarrage du container
        module_name = config_elem['name']
        self.__wait_container_event.clear()
        nom_image_docker = config_image['image']
        try:
            if config_image.get('container_mode'):
                self.__wait_start_container_name = nom_container_docker
                self.__gestionnaire_modules_docker.demarrer_container(nom_container_docker,
                                                                      nom_image=nom_image_docker,
                                                                      config=config_elem,
                                                                      images=gestionnaire_images_applications,
                                                                      application=nom_application)
            else:
                self.__wait_start_service_name = module_name
                self.__gestionnaire_modules_docker.demarrer_service(module_name,
                                                                    config=config_elem,
                                                                    images=gestionnaire_images_applications,
                                                                    nom_image=nom_image_docker,
                                                                    nom_container=nom_container_docker,
                                                                    application=nom_application)

            self.__wait_container_event.wait(60)
            if self.__wait_container_event.is_set() is False:
                raise Exception("Erreur demarrage " + module_name)
            self.__service_monitor.emettre_evenement('applicationDemarree', {'nom_application': module_name})
        except APIError as apie:
            if apie.status_code == 409:
                self.__logger.info("Service %s deja demarre" % self.__wait_start_service_name)
                self.__wait_container_event.set()
                self.__service_monitor.emettre_evenement(
                    'erreurDemarrageApplication',
                    {'nom_application': module_name, 'code': apie.status_code, 'err': str(apie)}
                )
            else:
                self.__logger.exception("Erreur demarrage service %s" % self.__wait_start_service_name)
                self.__service_monitor.emettre_evenement(
                    'erreurDemarrageApplication',
                    {'nom_application': module_name, 'code': apie.status_code, 'err': str(apie)}
                )
                raise apie
        finally:
            self.__wait_start_service_name = None  # Reset ecoute de l'evenement
            self.__wait_start_container_name = None  # Reset ecoute de l'evenement

    def effectuer_desinstallation(self, nom_image_docker):

        # Trouver le service/container en faisant la recherche des labels
        dict_app = self.__gestionnaire_modules_docker.trouver_application(nom_image_docker)
        for container in dict_app['containers']:
            nom_application = container.attrs['Config']['Labels']['application']

            container.stop()
            try:
                container.remove()
            except:
                pass  # Ok, container devrait se supprimer automatiquement
            self.__service_monitor.emettre_evenement('applicationArretee', {'nom_application': nom_application})

        for service in dict_app['services']:
            service.remove()
            nom_application = service.attrs['Spec']['Labels']['application']
            self.__service_monitor.emettre_evenement('applicationArretee', {'nom_application': nom_application})

    def trouver_applications_backup(self, commande: dict):

        configs = self.__gestionnaire_modules_docker.charger_configs('app.')

        for config in configs:
            config['configuration'] = json.loads(config['configuration'].decode('utf-8'))  # Parse json

        return configs

    def lancer_backup_applications(self, applications: list):
        for app in applications:
            configuration_docker = app.get('configuration')
            nom_application = app.get('nom_application')

            self.transmettre_evenement_backup(
                nom_application, Constantes.ConstantesBackup.EVENEMENT_BACKUP_APPLICATION_DEBUT)

            if nom_application is None:
                nom_application = configuration_docker['nom']

            if configuration_docker is None:
                # Charger la configuration a partir de configuration docker (app.cfg.NOM_APP)
                gestionnaire_docker = self.__service_monitor.gestionnaire_docker
                configuration_bytes = gestionnaire_docker.charger_config('app.cfg.' + nom_application)
                configuration_docker = json.loads(configuration_bytes)
                app['configuration'] = configuration_docker

            self.transmettre_evenement_backup(
                nom_application,
                Constantes.ConstantesBackup.EVENEMENT_BACKUP_APPLICATION_DEBUT
            )

            # tar_scripts = self.preparer_script_file(app)
            self.effectuer_backup(nom_application)

            self.transmettre_evenement_backup(nom_application,
                                              Constantes.ConstantesBackup.EVENEMENT_BACKUP_APPLICATION_TERMINE)

    def transmettre_evenement_backup(self, nom_application: str, action: str, info: dict = None,
                                     type_event=Constantes.ConstantesBackup.EVENEMENT_BACKUP_APPLICATION):
        evenement_contenu = {
            'nom_application': nom_application,
            'evenement': action,
        }
        if info is not None:
            evenement_contenu['info'] = info
        self.__service_monitor.generateur_transactions.emettre_message(
            evenement_contenu, type_event,
            exchanges=[Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS]
        )

    def effectuer_backup(self, nom_application: str):
        try:
            configuration_docker_bytes = self.__gestionnaire_modules_docker.charger_config(
                'app.cfg.' + nom_application)
            configuration_docker = json.loads(configuration_docker_bytes)
            configuration_backup = configuration_docker['backup']

            # Verifier si on a des dependances de backup
            try:
                dependances = configuration_backup['dependances']
            except KeyError:
                pass  # Aucunes dependances, OK
            else:
                # On a des dependances, preparer les scripts
                self.__logger.info("Preparer scripts de backup")

                for dep in dependances:
                    commande_backup = dep['commande_backup']
                    try:
                        image_info = configuration_docker['images'][dep['image']]
                    except KeyError:
                        image_info = None
                    self.__logger.info("Executer script dependance " + commande_backup)
                    self.__logger.info("Chiffrer et uploader les s fichiers sous /backup")
                    self._executer_service(nom_application, dep, commande_backup, image_info)

            try:
                # Lancer un container pour copier les volumes vers le repertoire de backup
                volumes = configuration_backup['data']['volumes']
                self.copier_volume_vers_backup(nom_application, volumes)
            except KeyError:
                pass  # OK

            # Emettre commande pour l'agent de backup d'applications, indique que tous les fichiers sont prets
            self.transmettre_commande_upload(nom_application)

            return {'ok': True}
        except Exception as e:
            self.__logger.exception("Erreur traitement backup")
            return {'ok': False, 'err': str(e)}

    def transmettre_commande_upload(self, nom_application):
        self.__logger.info("Transmettre commande pour chiffrer et uploader les s fichiers sous /backup")

        commande_backup_agent = {
            'url_serveur': 'https://mg-dev4:3021',
            'nom_application': nom_application,
        }
        domaine_action = 'commande.backupApplication.' + Constantes.ConstantesBackupApplications.COMMANDE_BACKUP_DECLENCHER_RESTAURER
        generateur_transactions = self.__service_monitor.generateur_transactions
        generateur_transactions.transmettre_commande(commande_backup_agent, domaine_action, ajouter_certificats=True)

    def effectuer_restauration(self, nom_application: str, configuration_docker):
        try:
            configuration_docker_bytes = self.__gestionnaire_modules_docker.charger_config(
                'app.cfg.' + nom_application)
            configuration_docker = json.loads(configuration_docker_bytes)
            configuration_backup = configuration_docker['backup']

            # Restaurer les fichiers
            commande = "python3 -m millegrilles.util.RestaurerApplication --debug"
            self._executer_service(nom_application, configuration_backup, commande)

            # Verifier si on a des dependances (scripts) de backup
            try:
                dependances = configuration_backup['dependances']
            except KeyError:
                # Aucunes dependances - rien a faire
                pass
            else:
                # On a des dependances, les scripts ont deja ete prepares par la restauration des fichiers
                dependances.reverse()  # On va executer les dependances dans l'ordre inverse du backup
                for dep in dependances:
                    commande_backup = dep['commande_restore']
                    try:
                        image_info = configuration_docker['images'][dep['image']]
                    except KeyError:
                        image_info = None
                    self.__logger.info("Executer script dependance " + commande_backup)
                    self.__logger.info("Chiffrer et uploader les s fichiers sous /backup")
                    self._executer_service(nom_application, dep, commande_backup, image_info)

            return {'ok': True}
        except Exception as e:
            self.__logger.exception("Erreur traitement backup")
            return {'ok': False, 'err': str(e)}

    def executer_commande(self, nom_application: str, commande: str):
        configuration_docker_bytes = self.__gestionnaire_modules_docker.charger_config('app.cfg.' + nom_application)
        configuration_docker = json.loads(configuration_docker_bytes)
        configuration_backup = configuration_docker['backup']

        self._executer_service(nom_application, configuration_backup, commande)

    def _executer_service(self, nom_application: str, configuration_commande: dict, commande: str, image: dict = None):
        configuration_contexte = self.__service_monitor.connexion_middleware.configuration

        docker_secrets_requis = [
            ('pki.monitor.key', 'pki.monitor.key'),
        ]

        # Ajouter mapping pour les secrets dans la configuration
        try:
            secrets_recents = configuration_commande['secrets']
            secrets_recents = [(s['name'], s['filename']) for s in secrets_recents]
            docker_secrets_requis.extend(secrets_recents)
        except KeyError:
            pass

        docker_config_requis = [
            ('pki.millegrille.cert', 'pki.millegrille.cert'),
            ('pki.monitor.cert', 'pki.monitor.cert'),
            ('app.cfg.' + nom_application, 'app.cfg.json'),
        ]

        # Identifier les secrets et configs
        secrets = list()
        for nom_secret in docker_secrets_requis:
            secret = self.__service_monitor.gestionnaire_docker.trouver_secret(nom_secret[0])

            secret_reference = dict()
            secret_reference['secret_id'] = secret['secret_id']
            secret_reference['secret_name'] = secret['secret_name']
            secret_reference['filename'] = '/run/secrets/' + nom_secret[1]
            secret_reference['uid'] = 0
            secret_reference['gid'] = 0
            secret_reference['mode'] = 0o444

            secrets.append(SecretReference(**secret_reference))

        configs = list()
        for nom_config in docker_config_requis:
            config = self.__service_monitor.gestionnaire_docker.charger_config_recente(nom_config[0])

            config_reference = config['config_reference']
            config_reference['filename'] = '/run/secrets/' + nom_config[1]
            config_reference['uid'] = 0
            config_reference['gid'] = 0
            config_reference['mode'] = 0o444
            configs.append(ConfigReference(**config_reference))

        var_env = [
            "MG_MQ_HOST=" + configuration_contexte.mq_host,
            "MG_MQ_PORT=%d" % configuration_contexte.mq_port,
            "MG_MQ_SSL=on",
            "MG_MQ_AUTH_CERT=on",
            "MG_MQ_CA_CERTS=/run/secrets/pki.millegrille.cert",
            "MG_MQ_KEYFILE=/run/secrets/pki.monitor.key",
            "MG_MQ_CERTFILE=/run/secrets/pki.monitor.cert",
            "CONFIG_APP=/run/secrets/app.cfg.json"
        ]

        # Ajouter les volumes implicites de scripts et backup
        rep_scripts = path.join(self.__scripts_volume, nom_application)
        rep_backup = path.join(self.__backup_volume, nom_application)

        # S'assurer que les repertoires existent
        makedirs(rep_scripts, mode=0o755, exist_ok=True)
        makedirs(rep_backup, mode=0o755, exist_ok=True)

        mounts = [
            # 'backup_%s:/backup:rw' % nom_application,
            '%s:/scripts:ro' % rep_scripts,
            '%s:/backup:rw' % rep_backup,
        ]

        try:
            volumes = configuration_commande['data']['volumes']
        except KeyError:
            pass
        else:
            for volume in volumes:
                mounts.append(':'.join([volume, '/backup/' + volume, 'rw']))

        docker_client = self.__gestionnaire_modules_docker.docker_client

        # Aller chercher l'image docker pour l'execution du script
        gestionnaire_images = GestionnaireImagesServices(configuration_contexte.idmg, docker_client)
        try:
            nom_image = image['image']
            tag = image['version']
        except (TypeError, KeyError):
            image_python = gestionnaire_images.telecharger_image_docker('mg-python')
        else:
            image_python = gestionnaire_images.get_image(nom_image, tag)

        try:
            service = docker_client.services.create(
                image_python.id,
                name="script_application",
                command=commande,
                mounts=mounts,
                env=var_env,
                configs=configs,
                secrets=secrets,
                user="root",
                networks=['millegrille_net'],
                restart_policy=RestartPolicy(condition='none', max_attempts=0),
                constraints=configuration_commande.get('constraints'),
                workdir="/scripts"
            )

            self.__wait_container_event.clear()
            self.__wait_start_service_name = service.name

            # Donner 10 secondes pour demarrer le service. L'image existe deja localement, pas de prep a faire.
            self.__wait_container_event.wait(10)

            if self.__wait_container_event.is_set() is False:
                raise ExceptionExecution("Erreur demarrage service script application pour " + nom_application, resultat=None)

            self.__wait_die_service_container_id = service.id
            self.__wait_event_die.clear()

            self.__wait_event_die.wait(600)  # Donner max de 10 minutes pour le backup

            # Verifier si la tache est en cours d'execution ou si elle a echoue
            service.reload()
            task = service.tasks()[0]
            if task['Status']['State'] == 'failed':
                exit_code = 'N/A'
                try:
                    exit_code = task['Status']['ContainerStatus']['ExitCode']
                except KeyError:
                    pass
                raise ExceptionExecution("Echec d'execution du script : " + str(exit_code), resultat=exit_code)

        finally:
            service = self.__gestionnaire_modules_docker.get_service('script_application')
            service.remove()

    def restore_dependance(self, gestionnaire_images_applications, config_image: dict, tar_scripts, tar_archive):
        nom_image_docker = config_image['image']
        backup_info = config_image['backup']
        config_elem = config_image['config']

        service_name = config_elem['name']
        self.__wait_start_service_name = service_name
        self.__wait_container_event.clear()

        self.__gestionnaire_modules_docker.demarrer_service(nom_image_docker,
                                                            config=config_elem,
                                                            images=gestionnaire_images_applications)

        self.__wait_container_event.wait(60)
        self.__wait_start_service_name = None  # Reset ecoute de l'evenement
        container_id = self.__wait_start_service_container_id
        self.__wait_start_service_container_id = None

        try:
            if self.__wait_container_event.is_set():
                self.__logger.info("Executer script de restauration du container id : %s" % self.__wait_start_service_container_id)
                self.__wait_container_event.clear()

                # Injecter le contenu du fichier .tar de backup
                path_archive = config_image['backup']['base_path']
                # Le path archive inclus le repertoire injecte dans l'archive (e.g. /tmp/backup, on veut extraire sous /tmp)
                path_archive = path.join('/', '/'.join(path_archive.split('/')[0:-1]))

                self.__gestionnaire_modules_docker.put_archives(container_id, tar_archive, path_archive)

                # Executer la restauration
                commande_restore = backup_info.get('commande_restore')
                if commande_restore:
                    self.__gestionnaire_modules_docker.executer_scripts(container_id, commande_restore, tar_scripts)
                else:
                    self.__logger.error("Erreur demarrage service (timeout) : %s" % nom_image_docker)
                    raise Exception("Image non installee : " + nom_image_docker)
        finally:
            self.__gestionnaire_modules_docker.supprimer_service(config_elem['name'])

    def initialiser_handler_mq(self, contexte):
        """
        Initialise le handler, le retourne pour le faire enregistrer comme listener sur MQ
        :param contexte:
        :return:
        """
        self.__handler_requetes = TraitementMQRequetesBlocking(contexte, self.__service_monitor.fermeture_event)
        return self.__handler_requetes


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

# Gestionnaire d'applications privees
import logging
import docker
import json
import secrets
import os
import tempfile
import tarfile
import io
import requests

from typing import Optional
from threading import Event
from typing import cast
from base64 import b64encode, b64decode
from os import path
from docker.errors import APIError

from millegrilles import Constantes
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker, GestionnaireImagesDocker
from millegrilles.monitor.MonitorConstantes import CommandeMonitor, ExceptionExecution, PkiCleNonTrouvee
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat
from millegrilles.util.BackupModule import HandlerBackupApplication
from millegrilles.dao.MessageDAO import TraitementMQRequetesBlocking
from millegrilles.util.Chiffrage import CipherMsg1Dechiffrer, DecipherStream

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

        self.__handler_requetes: [TraitementMQRequetesBlocking] = None

    def event(self, event):
        # self.__logger.debug("Event docker APPS : %s", str(event))

        if self.__wait_start_service_name or self.__wait_start_container_name:
            event_json = json.loads(event.decode('utf-8'))

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

        nom_application = commande.contenu['nom_application']
        configuration_docker = commande.contenu['configuration']
        tar_scripts = self.preparer_script_file(commande.contenu)
        self.preparer_installation(nom_application, configuration_docker, tar_scripts)

        # Transmettre maj
        self.__service_monitor.emettre_presence()

        return {'ok': True}

    def preparer_script_file(self, commande: dict):
        configuration = commande.get('configuration')
        if configuration and configuration.get('tar_xz'):
            b64_script = configuration['tar_xz']
            if b64_script:
                tar_bytes = b64decode(b64_script)
                file_handle, tar_scripts = tempfile.mkstemp(prefix='monitor-script-', suffix='.tar')
                os.close(file_handle)
                with open(tar_scripts, 'wb') as fichier:
                    fichier.write(tar_bytes)
        else:
            tar_scripts = commande.get('scripts_tarfile')
        return tar_scripts

    def supprimer_application(self, commande: CommandeMonitor):
        self.__logger.info("Supprimer application %s", str(commande))

        nom_application = commande.contenu['nom_application']
        self.effectuer_desinstallation(nom_application)

        # Transmettre maj
        self.__service_monitor.emettre_presence()

        return {'ok': True}

    def backup_application(self, commande: CommandeMonitor):
        self.__logger.info("Backup application %s", str(commande))

        applications = list()
        try:
            nom_image_docker = commande.contenu['nom_application']
            configuration_docker = commande.contenu.get('configuration')
            applications.append({'nom_application': nom_image_docker, 'configuration': configuration_docker})
        except KeyError:
            # On n'a pas d'application en particulier, lancer le backup de toutes les applications
            applications = self.trouver_applications_backup(commande.contenu)

        self.lancer_backup_applications(applications)

        # if configuration_docker is None:
        #     # Charger la configuration a partir de configuration docker (app.cfg.NOM_APP)
        #     gestionnaire_docker = self.__service_monitor.gestionnaire_docker
        #     configuration_bytes = gestionnaire_docker.charger_config('app.cfg.' + nom_image_docker)
        #     configuration_docker = json.loads(configuration_bytes)
        #     commande.contenu['configuration'] = configuration_docker
        #
        # tar_scripts = self.preparer_script_file(commande)
        # self.effectuer_backup(nom_image_docker, configuration_docker, tar_scripts)

    def restore_application(self, commande: CommandeMonitor):
        self.__logger.info("Restore application %s", str(commande))

        nom_image_docker = commande.contenu['nom_application']

        configuration_app = commande.contenu.get('configuration')
        if configuration_app is None:
            # Charger la configuration a partir de configuration docker (app.cfg.NOM_APP)
            gestionnaire_docker = self.__service_monitor.gestionnaire_docker
            configuration_bytes = gestionnaire_docker.charger_config('app.cfg.' + nom_image_docker)
            configuration_app = json.loads(configuration_bytes)
            commande.contenu['configuration'] = configuration_app

        tar_scripts = self.preparer_script_file({'configuration': configuration_app})

        liste_configurations = self.charger_dependances_restauration(configuration_app)
        # Conserver uniquement les images avec element backup, utiliser config.name comme nom de download
        liste_backup = list()
        for config in liste_configurations:
            if config.get('backup'):
                liste_backup.append(config)

        # Restaurer chaque application avec backup
        for config in liste_backup:
            nom_application = config['config']['name']

            # Preparer URL de connexion a consignationfichiers
            contexte = self.__handler_requetes.contexte
            configuration = contexte.configuration
            url_consignationfichiers = 'https://%s:%s' % (
                configuration.serveur_consignationfichiers_host,
                configuration.serveur_consignationfichiers_port
            )

            # Telecharger l'archive de backup la plus recente pour cette application
            certfile = configuration.mq_certfile
            keyfile = configuration.mq_keyfile

            r = requests.get(
                '%s/backup/application/%s' % (url_consignationfichiers, nom_application),
                verify=configuration.mq_cafile,
                cert=(certfile, keyfile)
            )

            archive_hachage = r.headers.get('archive_hachage')
            archive_nomfichier = r.headers.get('archive_nomfichier')
            archive_epoch = r.headers.get('estampille')

            # Demander la cle pour dechiffrer l'archive
            chaine_certs = contexte.signateur_transactions.chaine_certs
            requete = {
                'certificat': chaine_certs,
                'identificateurs_document': {
                    'archive_nomfichier': archive_nomfichier,
                },
            }
            resultat_cle = self.__handler_requetes.requete('MaitreDesCles.' + Constantes.ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE_BACKUP, requete)
            cle_dechiffree = contexte.signateur_transactions.dechiffrage_asymmetrique(resultat_cle['cle'])
            decipher = CipherMsg1Dechiffrer(b64decode(resultat_cle['iv']), cle_dechiffree)

            tar_archive = '/tmp/download.tar'
            iter_response = r.iter_content(chunk_size=64*1024)
            try:
                with open(tar_archive, 'wb') as fichier:
                    for data in iter_response:
                        # Dechiffrer, verifier hachage
                        data = decipher.update(data)
                        fichier.write(data)
                    fichier.write(decipher.finalize())

                # digest_calcule = decipher.digest  # Note : pas bon, il faut calculer avant data

                gestionnaire_images_applications = GestionnaireImagesApplications(
                    self.__service_monitor.idmg, self.__service_monitor.docker)
                gestionnaire_images_applications.set_configuration(configuration_app)
                self.restore_dependance(
                    gestionnaire_images_applications, config, tar_scripts, tar_archive)
            finally:
                # Cleanup
                fichiers_nettoyage = [tar_archive, tar_scripts]
                for fichier in fichiers_nettoyage:
                    try:
                        os.remove(fichier)
                    except FileNotFoundError:
                        pass

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

    def preparer_installation(self, nom_application, configuration_docker, tar_scripts=None, **kwargs):
        gestionnaire_images_applications = GestionnaireImagesApplications(
            self.__service_monitor.idmg, self.__service_monitor.docker)
        gestionnaire_images_applications.set_configuration(configuration_docker)

        config_name = 'app.cfg.' + nom_application

        self.__gestionnaire_modules_docker.sauvegarder_config(config_name, configuration_docker)

        # Installer toutes les dependances de l'application en ordre
        for config_image in configuration_docker['dependances']:
            if config_image.get('dependances'):
                mode_shared = config_image.get('shared')
                # Sous dependances presentes, c'est une sous-config
                nom_image_docker = config_image['nom']
                self.preparer_installation(nom_image_docker, config_image, shared=mode_shared)
            elif config_image.get('image'):
                # C'est une image, on l'installe
                try:
                    self.installer_dependance(gestionnaire_images_applications, config_image, tar_scripts)
                except APIError as api:
                    if api.status_code == 409 and kwargs.get('shared'):
                        pass  # OK
                    else:
                        raise api

        nginx_config = configuration_docker.get('nginx')
        if nginx_config:
            server_file = nginx_config.get('server_file')
            conf: Optional[str] = None
            if server_file:
                # Charger le fichier a partir de l'archive tar
                server_file_obj = io.BytesIO(b64decode(configuration_docker['tar_xz']))
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
            with open(path.join(path_nginx, server_file), 'w') as fichier:
                fichier.write(conf)

            # Redemarrer nginx
            nom_service_nginx = 'nginx'
            self.__gestionnaire_modules_docker.force_update_service(nom_service_nginx)

    def installer_dependance(self, gestionnaire_images_applications, config_image, tar_scripts=None):
        nom_container_docker = config_image['config']['name']
        config_name = 'docker.cfg.' + nom_container_docker
        config_elem = config_image['config']
        self.__gestionnaire_modules_docker.sauvegarder_config(config_name, config_elem)

        # Generer valeurs au besoin
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
                    self.__gestionnaire_modules_docker.sauvegarder_secret(label_motdepasse, motdepasse, ajouter_date=True)

        try:
            self.demarrer_application(config_elem, config_image, gestionnaire_images_applications, nom_container_docker)
        except PkiCleNonTrouvee:
            # La cle n'a pas ete trouvee, tenter de generer la cle/certificat et reessayer
            self.__service_monitor.regenerer_certificat(
                ConstantesGenerateurCertificat.ROLE_APPLICATION_PRIVEE,
                nom_container_docker,
                nomcle=nom_container_docker or config_elem['name']
            )
            self.demarrer_application(config_elem, config_image, gestionnaire_images_applications, nom_container_docker)

        if self.__wait_container_event.is_set():
            self.__logger.info("Executer script d'installation du container id : %s" % self.__wait_start_service_container_id)
            self.__wait_container_event.clear()

            # Preparer les scripts dans un fichier .tar temporaire
            # path_script = '/home/mathieu/PycharmProjects/millegrilles.consignation.python/test/scripts.apps.tar'
            # commande_script = '/tmp/apps/script.redmine.postgres.installation.sh'
            config_installation = config_image.get('installation')
            if config_installation:
                try:
                    self.__gestionnaire_modules_docker.executer_scripts(
                        self.__wait_start_service_container_id, config_installation['commande'], tar_scripts)
                except ExceptionExecution as ex:
                    codes_ok = config_installation.get('exit_codes_ok')
                    if not codes_ok or ex.resultat['exit'] not in codes_ok:
                        raise ex
        else:
            self.__logger.error("Erreur demarrage service (timeout) : %s" % nom_container_docker)
            raise Exception("Container non installe : " + nom_container_docker)

        if config_image.get('etape_seulement'):
            # C'est un service intermediaire pour l'installation/backup
            # On supprime le service maintenant que la tache est terminee
            self.__gestionnaire_modules_docker.supprimer_service(config_elem['name'])

    def demarrer_application(self, config_elem, config_image, gestionnaire_images_applications, nom_container_docker):
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
                                                                      images=gestionnaire_images_applications)
            else:
                self.__wait_start_service_name = module_name
                self.__gestionnaire_modules_docker.demarrer_service(module_name,
                                                                    config=config_elem,
                                                                    images=gestionnaire_images_applications,
                                                                    nom_image=nom_image_docker,
                                                                    nom_container=nom_container_docker)

            self.__wait_container_event.wait(60)
        except APIError as apie:
            if apie.status_code == 409:
                self.__logger.info("Service %s deja demarre" % self.__wait_start_service_name)
                self.__wait_container_event.set()
            else:
                self.__logger.exception("Erreur demarrage service %s" % self.__wait_start_service_name)
                raise apie
        finally:
            self.__wait_start_service_name = None  # Reset ecoute de l'evenement
            self.__wait_start_container_name = None  # Reset ecoute de l'evenement

    def effectuer_desinstallation(self, nom_image_docker):

        # Trouver le service/container en faisant la recherche des labels
        dict_app = self.__gestionnaire_modules_docker.trouver_application(nom_image_docker)
        for container in dict_app['containers']:
            container.stop()
            try:
                container.remove()
            except:
                pass  # Ok, container devrait se supprimer automatiquement

        for service in dict_app['services']:
            service.remove()

    def trouver_applications_backup(self, commande: dict):

        configs = self.__gestionnaire_modules_docker.charger_configs('app.')

        for config in configs:
            config['configuration'] = json.loads(config['configuration'].decode('utf-8'))  # Parse json

        return configs

    def lancer_backup_applications(self, applications: list):
        for app in applications:
            configuration_docker = app.get('configuration')
            nom_application = app.get('nom_application')

            if nom_application is None:
                nom_application = configuration_docker['nom']

            if configuration_docker is None:
                # Charger la configuration a partir de configuration docker (app.cfg.NOM_APP)
                gestionnaire_docker = self.__service_monitor.gestionnaire_docker
                configuration_bytes = gestionnaire_docker.charger_config('app.cfg.' + nom_application)
                configuration_docker = json.loads(configuration_bytes)
                app['configuration'] = configuration_docker

            tar_scripts = self.preparer_script_file(app)
            self.effectuer_backup(nom_application, configuration_docker, tar_scripts)

    def effectuer_backup(self, nom_image_docker, configuration_docker, tar_scripts=None):

        gestionnaire_images_applications = GestionnaireImagesApplications(
            self.__service_monitor.idmg, self.__service_monitor.docker)
        gestionnaire_images_applications.set_configuration(configuration_docker)

        for config_image in configuration_docker['dependances']:
            if config_image.get('dependances'):
                # Sous dependances presentes, c'est une sous-config (recursif)
                nom_image_docker = config_image['nom']
                self.effectuer_backup(nom_image_docker, config_image, tar_scripts)
            elif config_image.get('image'):
                # C'est une image, on l'installe
                if config_image.get('backup'):
                    self.backup_dependance(gestionnaire_images_applications, config_image, tar_scripts)

    def backup_dependance(self, gestionnaire_images_applications, config_image: dict, tar_scripts=None):
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

        if self.__wait_container_event.is_set():
            self.__logger.info("Executer script d'installation du container id : %s" % self.__wait_start_service_container_id)
            self.__wait_container_event.clear()

            try:
                # Preparer les scripts dans un fichier .tar temporaire
                commande_backup = backup_info.get('commande_backup')
                if commande_backup:
                    self.__gestionnaire_modules_docker.executer_scripts(container_id, commande_backup, tar_scripts)

                # Fin d'execution des scripts, on effectue l'extraction des fichiers du repertoire de backup
                path_archive = self.__gestionnaire_modules_docker.save_archives(
                    container_id, backup_info['base_path'], dest_prefix=config_elem['name'])

                handler_backup = HandlerBackupApplication(self.__handler_requetes)
                handler_backup.upload_backup(service_name, path_archive)

            finally:
                self.__gestionnaire_modules_docker.supprimer_service(config_elem['name'])

        else:
            self.__logger.error("Erreur demarrage service (timeout) : %s" % nom_image_docker)
            raise Exception("Image non installee : " + nom_image_docker)

    # def effectuer_restore(self, nom_image_docker, configuration_docker, tar_scripts: str, tar_archive: str):
    #     try:
    #         gestionnaire_images_applications = GestionnaireImagesApplications(
    #             self.__service_monitor.idmg, self.__service_monitor.docker)
    #         gestionnaire_images_applications.set_configuration(configuration_docker)
    #
    #         for config_image in configuration_docker['dependances']:
    #             if config_image.get('dependances'):
    #                 # Sous dependances presentes, c'est une sous-config (recursif)
    #                 nom_image_docker = config_image['nom']
    #                 self.effectuer_restore(nom_image_docker, config_image, tar_scripts, tar_archive)
    #             elif config_image.get('image'):
    #                 if config_image.get('backup'):
    #                     # C'est une image avec element de backup, on fait la restauration
    #                     self.restore_dependance(
    #                         gestionnaire_images_applications, config_image, tar_scripts, tar_archive)
    #     finally:
    #         # Cleanup scripts
    #         try:
    #             os.remove(tar_scripts)
    #         except FileNotFoundError:
    #             pass  # OK

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
        self.__handler_requetes = TraitementMQRequetesBlocking(contexte)
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

# Module de backup d'applications

class BackupApplication:

    def __init__(self):
        pass

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

        path_backup = backup_info['base_path']

        try:
            commande_backup = backup_info.get('commande_backup')
            if commande_backup is not None:
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
                    self.__logger.info(
                        "Executer script d'installation du container id : %s" % self.__wait_start_service_container_id)
                    self.__wait_container_event.clear()

                    # Preparer les scripts dans un fichier .tar temporaire

                    if commande_backup:
                        self.__gestionnaire_modules_docker.executer_scripts(container_id, commande_backup, tar_scripts)

                        # Fin d'execution des scripts, on effectue l'extraction des fichiers du repertoire de backup
                        path_archive = self.__gestionnaire_modules_docker.save_archives(
                            container_id, path_backup, dest_prefix=config_elem['name'])

                        # self.transmettre_evenement_backup(service_name,
                        #                                   Constantes.ConstantesBackup.EVENEMENT_BACKUP_APPLICATION_CATALOGUE_PRET)

                else:
                    self.__logger.error("Erreur demarrage service (timeout) : %s" % nom_image_docker)
                    raise Exception("Image non installee : " + nom_image_docker)

            volumes = backup_info.get('volumes')
            if volumes is not None:
                # Faire un backup de tous les volumes, generer un .tar.xz par volume
                self.__gestionnaire_modules_docker.executer_backup_volumes(volumes, path_backup)

            # Conserver toutes les archives generees dans un meme fichier .tar (pas compresse)
            archive_globale = path.join(path_backup, service_name + '.tar')

            fichier_tar = tarfile.open(archive_globale, mode='w')
            for fichier in os.listdir(path_backup):
                fichier_tar.add(path.join(path_backup, fichier))
            fichier_tar.close()

            handler_backup = HandlerBackupApplication(self.__handler_requetes)
            handler_backup.upload_backup(service_name, archive_globale)

        finally:
            self.__gestionnaire_modules_docker.supprimer_service(config_elem['name'])
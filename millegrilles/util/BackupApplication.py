# Module de backup d'applications
import logging
import json
import tarfile
import lzma
import datetime

from typing import Optional
from os import environ, listdir, path

from millegrilles.util.UtilScriptLigneCommandeMessages import ModeleConfiguration
from millegrilles.util.BackupModule import BackupUtil
from millegrilles.dao.MessageDAO import TraitementMQRequetesBlocking
from millegrilles import Constantes


class BackupApplication(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger('millegrilles.util.' + self.__class__.__name__)

        self.__configuration_application: Optional[dict] = None
        self.__handler_requetes: Optional[TraitementMQRequetesBlocking] = None
        self.__backup_util: Optional[BackupUtil] = None

        self.__nom_application: Optional[str] = None
        self.__catalogue_backup = dict()
        self.__transaction_maitredescles: Optional[dict] = None

        # Pipe d'output
        self.__output_file = None
        self.__cipher = None
        self.__lzma_compressor = None
        self.__tar_output = None

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        super().initialiser()
        self.__handler_requetes = TraitementMQRequetesBlocking(self.contexte)
        self.__backup_util = BackupUtil(self.contexte)
        # self.contexte.message_dao.register_channel_listener(self.__handler_requetes)

    def executer(self):
        self.__logger.info("Debut execution backup application")
        self.charger_environnement()

        self.preparer_cipher()
        self.executer_script_inclus()
        self.archiver_volumes()

        self.__tar_output.close()
        self.__lzma_compressor.close()
        self.__cipher.close()

    def charger_environnement(self):
        app_config_path = environ['CONFIG_APP']

        with open(app_config_path, 'r') as fichier:
            self.__configuration_application = json.load(fichier)

        self.__nom_application = self.__configuration_application['nom']
        self.preparer_catalogue()

        if self.__logger.isEnabledFor(logging.DEBUG):
            self.__logger.debug("Fichier de configuration\n%s", json.dumps(self.__configuration_application, indent=2))

    def preparer_catalogue(self):
        date_formattee = datetime.datetime.utcnow().strftime('%Y%m%d%H%M')
        nom_fichier_backup = 'application_%s_archive_%s.tar.xz.mgs1' % (self.__nom_application, date_formattee)
        nom_fichier_catalogue = 'application_%s_catalogue_%s.json' % (self.__nom_application, date_formattee)

        self.__catalogue_backup = {
            'application': self.__nom_application,
            'securite': Constantes.SECURITE_PROTEGE,
            Constantes.ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER: nom_fichier_backup,
            Constantes.ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER: nom_fichier_catalogue,
        }

    def preparer_cipher(self):
        # Faire requete pour obtenir les cles de chiffrage
        domaine_action = 'MaitreDesCles.' + Constantes.ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        cles_chiffrage = self.__handler_requetes.requete(domaine_action)
        self.__logger.debug("Cles chiffrage recu : %s" % cles_chiffrage)

        # Creer un fichier .tar.xz.mgs1 pour streamer le backup
        self.__output_file = open('/backup/output.tar.xz.mgs1', 'wb')

        cipher, transaction_maitredescles = self.__backup_util.preparer_cipher(
            self.__catalogue_backup, cles_chiffrage, nom_application=self.__nom_application,
            output_stream=self.__output_file
        )

        self.__logger.debug("Transaction maitredescles:\n%s", json.dumps(transaction_maitredescles, indent=2))
        self.__transaction_maitredescles = transaction_maitredescles

        self.__cipher = cipher
        self.__lzma_compressor = lzma.open(cipher, 'w')  # Pipe data vers le cipher
        self.__tar_output = tarfile.open(fileobj=self.__lzma_compressor, mode="w|")  # Pipe data vers lzma

        return cipher

    def ajouter_fichier(self, file_path: str):
        """
        Ajoute le fichier a l'archive .tar.xz.mgs1. Tronque le path.
        :param file_path:
        :return:
        """
        base_name = path.basename(file_path)
        self.__tar_output.add(file_path, arcname=base_name)

    def executer_script_inclus(self):
        """
        Execute le script inclus dans la configuration
        :return:
        """
        try:
            script_tar_xz = self.__configuration_application['backup']['script']
        except KeyError:
            self.__logger.info("Aucun script de backup fourni")
            return

        # Extraire le script vers /tmp

    def archiver_volumes(self):
        try:
            volumes = self.__configuration_application['backup']['volumes']
        except KeyError:
            self.__logger.info("Aucun volume de backup fourni")
            return

        self.__logger.info("Volumes dans le backup : %s" % str(volumes))

        self.__logger.debug("-----")
        self.__logger.debug("Directories sous /mnt")
        for dir in listdir('/mnt'):
            dir = path.join('/mnt', dir)
            self.__logger.debug("- %s" % dir)

        for volume in volumes:
            path_src = path.join('/mnt', volume)
            self.__tar_output.add(path_src, arcname=volume, recursive=True)

            # Creer un fichier .tar.xz pour le repertoire
            # with lzma.open(path_tarxz, 'w') as xz:
            #     with tarfile.open(fileobj=xz, mode='w|') as tar:
            #         tar.add(path_src, arcname=volume, recursive=True)

        self.__logger.debug("-----")

    def upload_archive(self):
        # handler_backup = HandlerBackupApplication(self.__handler_requetes)
        # handler_backup.upload_backup(nom_application, archive_globale)
        pass

    # def backup_dependance(self, gestionnaire_images_applications, config_image: dict, tar_scripts=None):
    #     nom_image_docker = config_image['image']
    #     backup_info = config_image['backup']
    #     config_elem = config_image['config']
    #     service_name = config_elem['name']
    #
    #     path_backup = backup_info['base_path']
    #
    #     try:
    #         commande_backup = backup_info.get('commande_backup')
    #         if commande_backup is not None:
    #             self.__wait_start_service_name = service_name
    #             self.__wait_container_event.clear()
    #
    #             self.__gestionnaire_modules_docker.demarrer_service(nom_image_docker,
    #                                                                 config=config_elem,
    #                                                                 images=gestionnaire_images_applications)
    #
    #             self.__wait_container_event.wait(60)
    #             self.__wait_start_service_name = None  # Reset ecoute de l'evenement
    #             container_id = self.__wait_start_service_container_id
    #             self.__wait_start_service_container_id = None
    #
    #             if self.__wait_container_event.is_set():
    #                 self.__logger.info(
    #                     "Executer script d'installation du container id : %s" % self.__wait_start_service_container_id)
    #                 self.__wait_container_event.clear()
    #
    #                 # Preparer les scripts dans un fichier .tar temporaire
    #
    #                 if commande_backup:
    #                     self.__gestionnaire_modules_docker.executer_scripts(container_id, commande_backup, tar_scripts)
    #
    #                     # Fin d'execution des scripts, on effectue l'extraction des fichiers du repertoire de backup
    #                     path_archive = self.__gestionnaire_modules_docker.save_archives(
    #                         container_id, path_backup, dest_prefix=config_elem['name'])
    #
    #                     # self.transmettre_evenement_backup(service_name,
    #                     #                                   Constantes.ConstantesBackup.EVENEMENT_BACKUP_APPLICATION_CATALOGUE_PRET)
    #
    #             else:
    #                 self.__logger.error("Erreur demarrage service (timeout) : %s" % nom_image_docker)
    #                 raise Exception("Image non installee : " + nom_image_docker)
    #
    #         volumes = backup_info.get('volumes')
    #         if volumes is not None:
    #             # Faire un backup de tous les volumes, generer un .tar.xz par volume
    #             self.__gestionnaire_modules_docker.executer_backup_volumes(volumes, path_backup)
    #
    #         # Conserver toutes les archives generees dans un meme fichier .tar (pas compresse)
    #         archive_globale = path.join(path_backup, service_name + '.tar')
    #
    #         fichier_tar = tarfile.open(archive_globale, mode='w')
    #         for fichier in os.listdir(path_backup):
    #             fichier_tar.add(path.join(path_backup, fichier))
    #         fichier_tar.close()
    #
    #         handler_backup = HandlerBackupApplication(self.__handler_requetes)
    #         handler_backup.upload_backup(service_name, archive_globale)
    #
    #     finally:
    #         self.__gestionnaire_modules_docker.supprimer_service(config_elem['name'])


if __name__ == '__main__':
    runner = BackupApplication()
    runner.main()

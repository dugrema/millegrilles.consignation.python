# Module de backup d'applications
import logging
import json
import tarfile
import lzma
import datetime
import subprocess
import sys

from typing import Optional
from os import environ, listdir, path, makedirs
from base64 import b64decode
from io import BytesIO

from millegrilles.util.UtilScriptLigneCommandeMessages import ModeleConfiguration
from millegrilles.util.BackupModule import BackupUtil, HandlerBackupApplication
from millegrilles.dao.MessageDAO import TraitementMQRequetesBlocking
from millegrilles import Constantes


class BackupApplication(ModeleConfiguration):

    FORMAT_HEURE = '%Y%m%d%H%M'

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger('millegrilles.util.' + self.__class__.__name__)

        self.__configuration_application: Optional[dict] = None
        self.__handler_requetes: Optional[TraitementMQRequetesBlocking] = None
        self.__backup_util: Optional[BackupUtil] = None

        self.__nom_application: Optional[str] = None
        self.__catalogue_backup = dict()
        self.__transaction_maitredescles: Optional[dict] = None

        self.__path_backup = '/backup'

        # Pipe d'output
        self.__output_stream = None
        self.__cipher = None
        self.__lzma_compressor = None
        self.__tar_output = None
        self.__path_output: Optional[str] = None

    def configurer_parser(self):
        super().configurer_parser()
        self.parser.add_argument(
            '--backup_upload', action="store_true", required=False,
            help="Chiffre et upload le contenu de /backup"
        )

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        super().initialiser()
        self.__handler_requetes = TraitementMQRequetesBlocking(self.contexte)
        self.__backup_util = BackupUtil(self.contexte)

    def executer(self):
        self.__logger.info("Debut execution preparation")
        self.charger_environnement()
        self.extraire_scripts_inclus()

        if self.args.backup_upload:
            self.__logger.info("Debut execution backup et upload application")
            self.executer_backup()

        self.__logger.info("Execution terminee")

    def executer_backup(self):
        self.preparer_cipher()
        # self.executer_script_inclus()  # Le script est maintenant execute separement
        self.archiver_volumes()

        self.__tar_output.close()
        self.__lzma_compressor.close()
        self.__cipher.close()

        self.__catalogue_backup[Constantes.ConstantesBackup.LIBELLE_ARCHIVE_HACHAGE] = self.__cipher.digest
        self.__transaction_maitredescles[Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES] = self.__cipher.digest

        self.upload()

    def upload(self):
        handler_backup = HandlerBackupApplication(self.contexte)
        handler_backup.upload_backup(self.__catalogue_backup, self.__transaction_maitredescles, self.__path_output)

    def charger_environnement(self):
        app_config_path = environ['CONFIG_APP']

        if self.__logger.isEnabledFor(logging.DEBUG):
            self.__logger.debug("Fichier de configuration\n%s", json.dumps(self.__configuration_application, indent=2))

        with open(app_config_path, 'r') as fichier:
            self.__configuration_application = json.load(fichier)

        self.__nom_application = self.__configuration_application['nom']
        self.preparer_catalogue()

        self.__path_output = path.join(
            '/tmp',
            self.__catalogue_backup[Constantes.ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER]
        )

        makedirs(self.__path_backup, exist_ok=True)

    def preparer_catalogue(self):
        date_formattee = datetime.datetime.utcnow().strftime(BackupApplication.FORMAT_HEURE)
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
        self.__output_stream = open(self.__path_output, 'wb')

        heure = datetime.datetime.utcnow().strftime(BackupApplication.FORMAT_HEURE)
        cipher, transaction_maitredescles = self.__backup_util.preparer_cipher(
            self.__catalogue_backup, cles_chiffrage, heure,
            nom_application=self.__nom_application,
            output_stream=self.__output_stream
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

    def extraire_scripts_inclus(self):
        """
        Extrait les scripts inclus dans la configuration
        :return:
        """
        try:
            script_tar_xz = self.__configuration_application['scripts']
        except KeyError:
            self.__logger.info("Aucun script de backup fourni")
            return

        # Ecrire le script sous /tmp/script.sh
        script_tar_xz = b64decode(script_tar_xz)
        script_tar_xz = BytesIO(script_tar_xz)
        with lzma.open(script_tar_xz, 'r') as xz:
            with tarfile.open(fileobj=xz, mode='r') as tar:
                tar.extractall('/scripts')

    def executer_script_inclus(self):
        """
        Execute le script de backup
        :return:
        """
        # Executer script de backup
        try:
            configuration_backup = self.__configuration_application['backup']
            commande_backup = path.join('/scripts', configuration_backup['commande_backup'])
        except KeyError:
            self.__logger.warning("Aucun script de backup inclus")
        else:
            subprocess.run(commande_backup, stdout=sys.stdout, check=True)

    def archiver_volumes(self):
        self.__logger.debug("-----")
        self.__logger.debug("Backup directory/file")
        for filedir in listdir(self.__path_backup):
            path_src = path.join(self.__path_backup, filedir)
            self.__logger.debug("- %s" % path_src)
            self.__tar_output.add(path_src, arcname=filedir, recursive=True)
        self.__logger.debug("-----")


if __name__ == '__main__':
    runner = BackupApplication()
    runner.main()

# Module de backup d'applications
import logging
import json
import tarfile
import lzma
import subprocess
import requests
import sys

from typing import Optional
from os import environ, path, makedirs
from base64 import b64decode
from io import BytesIO

from millegrilles.util.UtilScriptLigneCommandeMessages import ModeleConfiguration
from millegrilles.util.BackupModule import BackupUtil, WrapperDownload
from millegrilles.dao.MessageDAO import TraitementMQRequetesBlocking
from millegrilles import Constantes
from millegrilles.util.Chiffrage import CipherMsg1Dechiffrer, DecipherStream


class RestaurerApplication(ModeleConfiguration):

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
        self.__output_stream = None
        self.__cipher = None
        self.__lzma_compressor = None
        self.__tar_output = None
        self.__path_output: str = environ.get('PATH_RESTAURATION') or '/backup'

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        super().initialiser()
        self.__handler_requetes = TraitementMQRequetesBlocking(self.contexte)
        self.__backup_util = BackupUtil(self.contexte)

    def executer(self):
        self.__logger.info("Debut execution restauration application")
        self.charger_environnement()
        self.extraire_scripts_inclus()

        decipher_stream = self.preparer_decipher()
        self.extraire_archive(decipher_stream)
        # self.executer_script_inclus()

    def charger_environnement(self):
        app_config_path = environ['CONFIG_APP']

        with open(app_config_path, 'r') as fichier:
            self.__configuration_application = json.load(fichier)

        self.__nom_application = self.__configuration_application['nom']

        if self.__logger.isEnabledFor(logging.DEBUG):
            self.__logger.debug("Fichier de configuration\n%s", json.dumps(self.__configuration_application, indent=2))

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

    def preparer_decipher(self):
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
            '%s/backup/application/%s' % (url_consignationfichiers, self.__nom_application),
            verify=configuration.mq_cafile,
            cert=(certfile, keyfile),
            timeout=5.0
        )

        archive_hachage = r.headers.get('archive_hachage')
        archive_nomfichier = r.headers.get('archive_nomfichier')
        archive_epoch = r.headers.get('estampille')
        cle_header = r.headers.get('cle')
        iv_header = r.headers.get('iv')

        # Demander la cle pour dechiffrer l'archive
        chaine_certs = contexte.signateur_transactions.chaine_certs
        requete = {
            'certificat': chaine_certs,
            'identificateurs_document': {
                'archive_nomfichier': archive_nomfichier,
            },

            # Ajouter params pour recuperation de la cle
            'cle': cle_header, 'iv': iv_header, 'domaine': 'Applications',
        }
        resultat_cle = self.__handler_requetes.requete(
            'MaitreDesCles.' + Constantes.ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE_BACKUP, requete)
        cle_dechiffree = contexte.signateur_transactions.dechiffrage_asymmetrique(resultat_cle['cle'])
        decipher = CipherMsg1Dechiffrer(b64decode(resultat_cle['iv']), cle_dechiffree)

        wrapper = WrapperDownload(r.iter_content(chunk_size=10 * 1024))
        decipher_stream = DecipherStream(decipher, wrapper)

        return decipher_stream

    # def ajouter_fichier(self, file_path: str):
    #     """
    #     Ajoute le fichier a l'archive .tar.xz.mgs1. Tronque le path.
    #     :param file_path:
    #     :return:
    #     """
    #     base_name = path.basename(file_path)
    #     self.__tar_output.add(file_path, arcname=base_name)
    #
    # def executer_script_inclus(self):
    #     """
    #     Execute le script inclus dans la configuration
    #     :return:
    #     """
    #     try:
    #         configuration_backup = self.__configuration_application['backup']
    #         script_tar_xz = self.__configuration_application['scripts']
    #     except KeyError:
    #         self.__logger.info("Aucun script de backup fourni")
    #         return
    #
    #     makedirs('/tmp/scripts', exist_ok=True)
    #
    #     # Ecrire le script sous /tmp/script.sh
    #     script_tar_xz = b64decode(script_tar_xz)
    #     script_tar_xz = BytesIO(script_tar_xz)
    #     with lzma.open(script_tar_xz, 'r') as xz:
    #         with tarfile.open(fileobj=xz, mode='r') as tar:
    #             tar.extractall('/tmp/scripts')
    #
    #     # Executer script de backup
    #     commande_backup = path.join('/tmp/scripts', configuration_backup['commande_restore'])
    #     subprocess.run(commande_backup, stdout=sys.stdout, check=True)

    def extraire_archive(self, decipher_stream):
        with lzma.open(decipher_stream, 'r') as xz:
            with tarfile.open(fileobj=xz, mode='r|') as tar:
                tar.extractall(self.__path_output)


if __name__ == '__main__':
    runner = RestaurerApplication()
    runner.main()

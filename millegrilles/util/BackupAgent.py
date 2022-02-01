# Module de backup d'applications
import logging
import json
import tarfile
import lzma
import datetime
import multibase
import glob
import requests
import shutil

from typing import Optional
from os import listdir, path, makedirs, remove

from millegrilles.util.UtilScriptLigneCommandeMessages import ModeleConfiguration
from millegrilles.util.BackupModule import BackupUtil, HandlerBackupApplication, WrapperDownload
from millegrilles.dao.MessageDAO import TraitementMQRequetesBlocking, BaseCallback
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup, ConstantesBackupApplications, ConstantesMaitreDesCles
from millegrilles.util.Chiffrage import DecipherStream, CipherMgs3Dechiffrer


class BackupAgent(ModeleConfiguration):

    FORMAT_HEURE = '%Y%m%d%H%M'

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger('millegrilles.util.' + self.__class__.__name__)

        self.__configuration_application: Optional[dict] = None
        self.__handler_requetes: Optional[TraitementMQRequetesBlocking] = None
        self.__backup_util: Optional[BackupUtil] = None

        self.__nom_application: Optional[str] = None
        self.__catalogue_backup = dict()
        # self.__transaction_maitredescles: Optional[dict] = None

        self.__path_backup = '/var/opt/millegrilles/consignation/backup_app_work'

        # self.__event_fermeture = Event()

        self.queue_name = None
        self.__traitement_message = None

        # Pipe d'output
        self.__output_stream = None
        self.__cipher = None
        self.__lzma_compressor = None
        self.__tar_output = None
        self.__path_output: Optional[str] = None
        self.__channel = None

    def configurer_parser(self):
        super().configurer_parser()
        self.parser.add_argument(
            '--backup_upload', action="store_true", required=False,
            help="Chiffre et upload le contenu de /backup"
        )

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        super().initialiser()
        self.__handler_requetes = TraitementMQRequetesBlocking(self.contexte, self._fermeture_event)
        self.__backup_util = BackupUtil(self.contexte)
        self.__traitement_message = TraiterMessage(self.contexte, self._fermeture_event, self)

        self.contexte.message_dao.register_channel_listener(self.__traitement_message)

    def executer(self):
        self.__logger.info("Debut execution preparation")
        self.charger_environnement()
        # self.extraire_scripts_inclus()

        while not self._fermeture_event.is_set():
            # Entretien
            self._fermeture_event.wait(30)

        self.__logger.info("Execution terminee")

    def executer_backup(self, params: dict):
        nom_application = params['nom_application']
        url_serveur = params.get('url_serveur')
        rep_src = path.join(self.__path_backup, nom_application)

        try:
            catalogue_backup = self.preparer_catalogue(nom_application)

            path_output = path.join(
                '/tmp/mg_backup_app',
                catalogue_backup[Constantes.ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER]
            )

            makedirs('/tmp/mg_backup_app', mode=0o770, exist_ok=True)

            streams = self.preparer_cipher(nom_application, catalogue_backup, path_output)
            cipher = streams['cipher']
            transaction_maitredescles = streams['maitredescles']
            lzma_compressor = streams['lzma']
            tar_output = streams['tar']

            # self.executer_script_inclus()  # Le script est maintenant execute separement
            self.archiver_volumes(rep_src, tar_output)

            tar_output.close()
            lzma_compressor.close()
            cipher.close()

            digest_archive = cipher.digest
            tag = multibase.encode('base64', cipher.tag).decode('utf-8')

            # Mettre digest et tag dans catalogue
            catalogue_backup[Constantes.ConstantesBackup.LIBELLE_ARCHIVE_HACHAGE] = digest_archive
            catalogue_backup[Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG] = tag

            # Mettre digest et tag dans transaction de maitre des cles
            transaction_maitredescles[Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES] = digest_archive
            transaction_maitredescles[Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG] = tag

            self.upload(catalogue_backup, transaction_maitredescles, path_output, url_serveur=url_serveur)

            # Cleanup tmp
            rm_files = glob.glob('/tmp/mg_backup_app/*')
            for rm_f in rm_files:
                try:
                    remove(rm_f)
                except IOError:
                    pass  # ok
        except Exception as e:
            self.__logger.exception("Erreur demarrage backup")
            return {'ok': False, 'err': str(e)}
        else:
            return {'ok': True}

    def executer_restaurer(self, params: dict):
        nom_application = params['nom_application']
        url_serveur = params.get('url_serveur')

        restaurateur = RestaurerApplication(
            self.contexte,
            self.__handler_requetes,
            self.__backup_util,
            nom_application,
            self.__path_backup,
            url_serveur)

        return restaurateur.executer()

    def upload(self, catalogue_backup: dict, transaction_maitredescles: dict, path_fichiers: str, url_serveur: str = None):
        self.__logger.info("Upload fichier backup application")
        handler_backup = HandlerBackupApplication(self.contexte, url_serveur=url_serveur)
        handler_backup.upload_backup(catalogue_backup, transaction_maitredescles, path_fichiers)
        self.__logger.info("Fin upload fichier backup application")

    def charger_environnement(self):
        if self.__logger.isEnabledFor(logging.DEBUG):
            self.__logger.debug("Fichier de configuration\n%s", json.dumps(self.__configuration_application, indent=2))

    def preparer_catalogue(self, nom_application: str):
        date_formattee = datetime.datetime.utcnow().strftime(BackupAgent.FORMAT_HEURE)
        nom_fichier_backup = 'application_%s_archive_%s.tar.xz.mgs2' % (nom_application, date_formattee)
        nom_fichier_catalogue = 'application_%s_catalogue_%s.json' % (nom_application, date_formattee)

        catalogue_backup = {
            'application': nom_application,
            'securite': Constantes.SECURITE_PROTEGE,
            Constantes.ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER: nom_fichier_backup,
            Constantes.ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER: nom_fichier_catalogue,
        }

        return catalogue_backup

    def preparer_cipher(self, nom_application: str, catalogue_backup: dict, path_output: str):
        # Faire requete pour obtenir les cles de chiffrage
        domaine_action = 'MaitreDesCles.' + Constantes.ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        cles_chiffrage = self.__handler_requetes.requete(domaine_action)
        self.__logger.debug("Cles chiffrage recu : %s" % cles_chiffrage)

        # Creer un fichier .tar.xz.mgs2 pour streamer le backup
        output_stream = open(path_output, 'wb')

        heure = datetime.datetime.utcnow().strftime(BackupAgent.FORMAT_HEURE)
        cipher, transaction_maitredescles = self.__backup_util.preparer_cipher(
            catalogue_backup, cles_chiffrage, heure,
            nom_application=nom_application,
            output_stream=output_stream
        )

        self.__logger.debug("Transaction maitredescles:\n%s", json.dumps(transaction_maitredescles, indent=2))

        lzma_compressor = lzma.open(cipher, 'w')  # Pipe data vers le cipher
        tar_output = tarfile.open(fileobj=lzma_compressor, mode="w|")  # Pipe data vers lzma

        return {'cipher': cipher, 'maitredescles': transaction_maitredescles, 'lzma': lzma_compressor, 'tar': tar_output}

    def ajouter_fichier(self, file_path: str):
        """
        Ajoute le fichier a l'archive .tar.xz.mgs2. Tronque le path.
        :param file_path:
        :return:
        """
        base_name = path.basename(file_path)
        self.__tar_output.add(file_path, arcname=base_name)

    def archiver_volumes(self, path_backup: str, tar_output):
        self.__logger.debug("-----")
        self.__logger.debug("Backup directory/file")
        for filedir in listdir(path_backup):
            path_src = path.join(path_backup, filedir)
            self.__logger.debug("- %s" % path_src)
            tar_output.add(path_src, arcname=filedir, recursive=True)
        self.__logger.debug("-----")


class TraiterMessage(BaseCallback):

    def __init__(self, contexte, fermeture_event, agent):
        super().__init__(contexte)
        self.__fermeture_event = fermeture_event
        self.__agent = agent
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__channel = None

    def on_channel_open(self, channel):
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel

        channel.queue_declare('', durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        self.__channel.basic_consume(self.queue_name, self.callbackAvecAck, auto_ack=False)

        routing_keys = [
            'commande.backupApplication.backup',
            'commande.backupApplication.restaurer',
        ]

        for rk in routing_keys:
            self.__channel.queue_bind(
                queue=self.queue_name,
                exchange=Constantes.SECURITE_PROTEGE,
                routing_key=rk,
                callback=None
            )

    def on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.__logger.warning("MQ Channel ferme")
        if not self.__fermeture_event.is_set():
            self.contexte.message_dao.enter_error_state()

    def __on_return(self, channel, method, properties, body):
        pass

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        action = routing_key.split('.').pop()

        self.__logger.debug("Message recu : %s" % message_dict)
        if action == ConstantesBackupApplications.COMMANDE_BACKUP_DECLENCHER_BACKUP:
            self.ack_init(message_dict, properties)
            reponse = self.__agent.executer_backup(message_dict)
        elif action == ConstantesBackupApplications.COMMANDE_BACKUP_DECLENCHER_RESTAURER:
            self.ack_init(message_dict, properties)
            reponse = self.__agent.executer_restaurer(message_dict)
        else:
            self.__logger.error("Type de message inconnu : %s" % action)
            return

        if reponse:
            if not isinstance(reponse, dict):
                reponse = {'resultat': reponse}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)

    def ack_init(self, message, properties):
        ack_init = {'ok': True, 'event': 'debut'}
        self.transmettre_reponse(message, ack_init, properties.reply_to, properties.correlation_id)

    def transmettre_reponse(self, requete, resultats, replying_to, correlation_id=None, ajouter_certificats=False):
        if replying_to is None:
            return  # Rien a faire

        if correlation_id is None:
            correlation_id = requete[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        self.contexte.generateur_transactions.transmettre_reponse(
            resultats, replying_to, correlation_id, ajouter_certificats=ajouter_certificats)


class RestaurerApplication:
    """
    Classe utilitaire de restauration d'une application
    """

    def __init__(
            self, contexte,
            handler_requetes: TraitementMQRequetesBlocking,
            backup_util: BackupUtil,
            nom_application: str,
            path_output: str,
            url_serveur: str = None
    ):
        self.__contexte = contexte
        self.__handler_requetes: Optional[TraitementMQRequetesBlocking] = None
        self.__backup_util: Optional[BackupUtil] = None
        self.__nom_application = nom_application
        self.__path_output = path_output
        self.__url_serveur = url_serveur

        self.__logger = logging.getLogger('millegrilles.util.' + self.__class__.__name__)
        self.__configuration_application: Optional[dict] = None

        self.__catalogue_backup = dict()
        self.__transaction_maitredescles: Optional[dict] = None

        # Pipe d'output
        self.__output_stream = None
        self.__cipher = None
        self.__lzma_compressor = None
        self.__tar_output = None

        self.__handler_requetes = handler_requetes
        self.__backup_util = backup_util

    def executer(self):
        try:
            self.__logger.info("Debut execution restauration application")
            decipher_stream = self.preparer_decipher()
            self.extraire_archive(decipher_stream)
            return {'ok': True}
        except Exception as e:
            self.__logger.exception("Erreur traitement restauration")
            return {'ok': False, 'err': str(e)}

    def preparer_decipher(self):
        # Preparer URL de connexion a consignationfichiers
        contexte = self.__handler_requetes.contexte
        configuration = contexte.configuration

        url_consignationfichiers = self.__url_serveur
        if url_consignationfichiers is None:
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
            timeout=5.0,
            stream=True,
        )

        r.raise_for_status()

        headers = r.headers
        self.__logger.info("Headers recus : %s" % str(headers))
        archive_hachage = r.headers.get('archive_hachage')
        cle_header = r.headers.get('cle')
        iv_header = r.headers.get('iv')
        tag_header = r.headers.get('tag')
        format_header = r.headers.get('format_chiffrage')

        # Demander la cle pour dechiffrer l'archive
        chaine_certs = contexte.signateur_transactions.chaine_certs
        requete = {
            'certificat': chaine_certs,

            # Ajouter params pour recuperation de la cle
            ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLE: cle_header,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV: iv_header,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG: tag_header,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT: format_header,

            # Info pour trouver la cle
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: ConstantesBackup.DOMAINE_NOM,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: [archive_hachage],
        }
        resultat_cle = self.__handler_requetes.requete(
            'MaitreDesCles.' + Constantes.ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE, requete)
        if resultat_cle['acces'] != '1.permis':
            if resultat_cle['acces'] == '4.inconnue':
                self.__logger.info("Emettre la cle du backup vers CA pour rechiffrage")
                emettre_cle(
                    self.__contexte, archive_hachage, cle_header, iv_header, tag_header, format_header,
                    "Backup", {"application": self.__nom_application, "cle_restauree": 'true'}
                )

            raise Exception("Acces refuse (%s) a la cle pour le backup d'application %s" % (resultat_cle['acces'], self.__nom_application))
        cle = resultat_cle['cles'][archive_hachage]

        cle_dechiffree = CipherMgs3Dechiffrer.dechiffrer_cle(contexte.configuration.cle, cle['cle'])
        decipher = CipherMgs3Dechiffrer(cle['iv'], cle_dechiffree, compute_tag=cle['tag'])

        wrapper = WrapperDownload(r.iter_content(chunk_size=10 * 1024))
        decipher_stream = DecipherStream(decipher, wrapper)

        return decipher_stream

    def extraire_archive(self, decipher_stream):
        path_output_app = path.join(self.__path_output, self.__nom_application)

        rm_files = glob.glob(path.join(path_output_app, '*'))
        for rm_f in rm_files:
            if path.isdir(rm_f):
                shutil.rmtree(rm_f)
            else:
                remove(rm_f)

        self.__logger.debug("Extraction de l'archive vers %s" % path_output_app)
        with lzma.open(decipher_stream, 'r') as xz:
            with tarfile.open(fileobj=xz, mode='r|') as tar:
                tar.extractall(path_output_app)


def emettre_cle(contexte, hachage_bytes, cle, iv, tag, format, domaine, id_doc: dict):
    fingerprint = contexte.configuration.certificat_millegrille.fingerprint
    print("Emettre fingerprint_ca: %s = cle %s: iv: %s, tag: %s, format: %s, cle: %s" % (fingerprint, hachage_bytes, iv, tag, format, cle))

    message_cle = {
        "domaine": domaine,
        "hachage_bytes": hachage_bytes,
        "cles": {fingerprint: cle},
        "iv": iv,
        "tag": tag,
        "format": format,
        "identificateurs_document": id_doc
    }
    generateur_transactions = contexte.generateur_transactions
    generateur_transactions.transmettre_commande(message_cle, domaine="MaitreDesCles", action="sauvegarderCle", ajouter_certificats=True)


if __name__ == '__main__':
    runner = BackupAgent()
    runner.main()

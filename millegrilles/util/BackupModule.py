import logging
import datetime
import pytz
import json
import lzma
import hashlib
import requests
import tarfile

from typing import Optional, List, Dict
from io import RawIOBase
from os import path, unlink
from pathlib import Path
from base64 import b64encode, b64decode
from lzma import LZMAFile, LZMAError
from threading import Thread, Event
from operator import attrgetter

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup
from millegrilles.util.JSONMessageEncoders import BackupFormatEncoder, DateFormatEncoder, decoder_backup
from millegrilles.SecuritePKI import HachageInvalide, CertificatInvalide, CertificatInconnu, EnveloppeCertificat
from millegrilles.util.X509Certificate import EnveloppeCleCert
from millegrilles.util.Chiffrage import CipherMsg1Chiffrer, CipherMsg1Dechiffrer, DecipherStream, DigestStream
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import TraitementMessageCallback


# class CipherIOWriter(RawIOBase):
#
#     def __init__(self, cipher: CipherMsg1Chiffrer, output_stream):
#         self.__cipher = cipher
#         self.__output_stream = output_stream
#
#         # Demarrer le chiffrage
#         self.__output_stream.write(self.__cipher.start_encrypt())
#
#     def write(self, __b) -> Optional[int]:
#
#         # Chiffrer
#         data_chiffre = self.__cipher.update(__b)
#
#         return self.__output_stream.write(data_chiffre)
#
#     def close(self):
#         # Finaliser cipher
#         self.__output_stream.write(self.__cipher.finalize())
#
#         self.__output_stream.close()
#
#     def digest(self):
#         return self.__cipher.digest

class InformationSousDomaineHoraire:
    """
    Information cumulee durant le backup d'un groupe sous-domaine/heure
    """

    CLES_SET = frozenset(['certificats_millegrille', 'certificats_intermediaires', 'certificats', 'fuuid_grosfichiers'])

    def __init__(self, nom_collection_mongo: str, sous_domaine: str, heure: datetime.datetime, snapshot=False):
        self.nom_collection_mongo = nom_collection_mongo
        self.sous_domaine = sous_domaine
        self.snapshot = snapshot

        # Information temporelle
        self.heure = heure
        self.heure_fin: Optional[datetime.datetime] = None

        # Chiffrage et securite
        self.chainage_backup_precedent: Optional[dict] = None
        self.info_cles: Optional[dict] = None
        self.transaction_maitredescles: Optional[dict] = None
        self.cipher = None

        # Fichiers et catalogue
        self.path_fichier_backup: Optional[str] = None
        self.path_fichier_catalogue: Optional[str] = None
        self.path_fichier_maitrecles: Optional[str] = None
        self.catalogue_backup: Optional[dict] = None
        self.sha512_backup: Optional[str] = None
        self.sha512_catalogue: Optional[str] = None

        # Detail du contenu de backup
        self.uuid_transactions = list()      # UUID des transactions inclues dans le backup
        self.liste_uuids_invalides = list()  # UUID des transactions qui ne peuvent etre traitees

    @property
    def nom_fichier_backup(self) -> str:
        return path.basename(self.path_fichier_backup)

    @property
    def nom_fichier_catalogue(self) -> str:
        return path.basename(self.path_fichier_catalogue)

    @property
    def backup_workdir(self) -> str:
        return path.dirname(self.path_fichier_backup)

    def cleanup(self):
        """
        Supprime les fichiers temporaires
        :return:
        """
        fichiers = [self.path_fichier_backup, self.path_fichier_catalogue, self.path_fichier_maitrecles]
        for fichier in fichiers:
            try:
                unlink(fichier)
            except (FileNotFoundError, TypeError):
                pass


class GroupeSousdomaine:

    def __init__(self):
        self.__liste_horaire = sorted(list(), key=attrgetter('heure'))
        self.__sous_domaine = None

    def append(self, information_sousdomaine: InformationSousDomaineHoraire):
        """
        Ajoute sous-domaine pour une heure. S'assure que le sous-domaine correspond aux autres heures.
        """
        domaine = information_sousdomaine.sous_domaine
        if self.__sous_domaine is None:
            self.__sous_domaine = domaine
        elif self.__sous_domaine != domaine:
            raise ValueError("Mismatch sous-domaine: %s != %s" % (self.__sous_domaine, domaine))

        self.__liste_horaire.append(information_sousdomaine)

    @property
    def liste_horaire(self) -> List[InformationSousDomaineHoraire]:
        return self.__liste_horaire


class BackupUtil:

    def __init__(self, contexte):
        self.__contexte = contexte
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def preparer_cipher(
            self, catalogue_backup, info_cles: dict, heure_str: str,
            nom_domaine: str = None, nom_application: str = None, output_stream=None):
        """
        Prepare un objet cipher pour chiffrer le fichier de transactions

        :param catalogue_backup: Catalogue de backup horaire
        :param info_cles: Cles publiques (certs) retournees par le maitre des cles. Utilisees pour chiffrer cle secrete.
        :param output_stream: Optionnel, stream/fichier d'output. Permet d'utiliser le cipher comme output stream dans un pipe.
        :return:
        """
        cipher = CipherMsg1Chiffrer(output_stream=output_stream)
        iv = b64encode(cipher.iv).decode('utf-8')

        # Conserver iv et cle chiffree avec cle de millegrille (restore dernier recours)
        enveloppe_millegrille = self.__contexte.signateur_transactions.get_enveloppe_millegrille()
        catalogue_backup['cle'] = b64encode(cipher.chiffrer_motdepasse_enveloppe(enveloppe_millegrille)).decode('utf-8')
        catalogue_backup['iv'] = iv

        # Generer transaction pour sauvegarder les cles de ce backup avec le maitredescles
        certs_cles_backup = [
            info_cles['certificat'][0],  # Certificat de maitredescles
            info_cles['certificat_millegrille'],  # Certificat de millegrille
        ]
        certs_cles_backup.extend(info_cles['certificats_backup'].values())
        cles_chiffrees = self.chiffrer_cle(certs_cles_backup, cipher.password)

        identificateurs_document = {
            'heure': heure_str
        }
        if nom_domaine is not None:
            identificateurs_document['domaine'] = nom_domaine
        if nom_application is not None:
            identificateurs_document['application'] = nom_application

        transaction_maitredescles = {
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateurs_document,
            'iv': iv,
            'cles': cles_chiffrees,
            'domaine': ConstantesBackup.DOMAINE_NOM,
        }

        return cipher, transaction_maitredescles

    def chiffrer_cle(self, pems: list, cle_secrete: bytes):
        cles = dict()
        for pem in pems:
            clecert = EnveloppeCleCert()
            clecert.cert_from_pem_bytes(pem.encode('utf-8'))
            fingerprint_b64 = clecert.fingerprint_b64
            cle_chiffree, fingerprint = clecert.chiffrage_asymmetrique(cle_secrete)

            cle_chiffree_b64 = b64encode(cle_chiffree).decode('utf-8')
            cles[fingerprint_b64] = cle_chiffree_b64

        return cles


class HandlerBackupDomaine:
    """
    Gestionnaire de backup des transactions d'un domaine.
    """

    BUFFER_SIZE = 512 * 1024  # 512 KB

    def __init__(self, contexte, nom_domaine, nom_collection_transactions, nom_collection_documents,
                 niveau_securite=Constantes.SECURITE_PROTEGE):
        self._contexte = contexte
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._nom_domaine = nom_domaine
        self._nom_collection_transactions = nom_collection_transactions
        self._nom_collection_documents = nom_collection_documents
        self.__niveau_securite = niveau_securite
        self.__backup_util = BackupUtil(contexte)

    def backup_horaire_domaine(self, heure: datetime.datetime, info_cles: dict, snapshot=False):
        """
        Effectue le backup horaire pour un domaine.

        :param heure: Heure du backup horaire
        :param info_cles: Reponse de requete ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        :param snapshot: Si True, effectue un snapshot plutot qu'un backup horaire
        """
        debut_backup = heure
        try:
            # Progress update - debut backup horaire
            self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_DEBUT, debut_backup)

            sousgroupes = self.preparer_sousgroupes_horaires(heure)

            heure_plus_vieille = None

            for domaine, sousgroupe in sousgroupes.items():
                entete_backup_precedent: Optional[dict] = None

                # Transmettre info de debut de backup au client
                for information_sousgroupe in sousgroupe.liste_horaire:
                    information_sousgroupe.snapshot = snapshot

                    if entete_backup_precedent is None:
                        # Trouver le plus recent backup
                        entete_backup_precedent = self.trouver_entete_backup_precedent(information_sousgroupe.sous_domaine)

                    # Preparer chainange avec plus recent backup
                    try:
                        chainage_backup_precedent = {
                            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: entete_backup_precedent[
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
                            ConstantesBackup.LIBELLE_HACHAGE_ENTETE: self.calculer_hash_entetebackup(
                                entete_backup_precedent)
                        }
                    except (TypeError, KeyError):
                        # C'est le premier backup de la chaine
                        chainage_backup_precedent = None

                    information_sousgroupe.chainage_backup_precedent = chainage_backup_precedent
                    information_sousgroupe.info_cles = info_cles

                    self._preparation_backup_horaire(information_sousgroupe)
                    self._execution_backup_horaire(information_sousgroupe)

                    if information_sousgroupe.catalogue_backup is not None:
                        # Uploader les fichiers et transactions de backup vers consignationfichiers
                        with open(information_sousgroupe.path_fichier_backup, 'rb') as fp_transactions:
                            with open(information_sousgroupe.path_fichier_catalogue, 'rb') as fp_catalogue:
                                fp_maitrecles = None
                                if information_sousgroupe.path_fichier_maitrecles is not None:
                                    fp_maitrecles = open(information_sousgroupe.path_fichier_maitrecles, 'rb')
                                self.uploader_fichiers_backup(information_sousgroupe, fp_transactions, fp_catalogue, fp_maitrecles)
                                if fp_maitrecles is not None:
                                    try:
                                        fp_maitrecles.close()
                                    except IOError as ioe:
                                        self.__logger.warning("Erreur fermeture fp_maitredescles : %s" % str(ioe))

                        if not information_sousgroupe.snapshot:
                            self.soumettre_transactions_backup_horaire(information_sousgroupe)

                        # Calculer nouvelle entete
                        entete_backup_precedent = information_sousgroupe.catalogue_backup[
                            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]

                        # Conserver l'heure la plus vieille de ce backup - utilise pour trigger backup quotidien
                        if heure_plus_vieille is None or heure_plus_vieille > information_sousgroupe.heure:
                            heure_plus_vieille = information_sousgroupe.heure

                    else:
                        self.__logger.warning(
                            "Aucune transaction valide inclue dans le backup de %s a %s mais transactions en erreur presentes" % (
                                self._nom_collection_transactions, str(information_sousgroupe.heure))
                        )

                # Progress update - backup horaire termine
                self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_TERMINE, debut_backup)

            # Aucun backup a faire, s'assurer de transmettre le trigger pour le backup quotidien precedent
            if heure_plus_vieille is None:
                heure_plus_vieille = heure - datetime.timedelta(hours=1)

            # Declencher backup quotidien
            self.transmettre_trigger_jour_precedent(heure_plus_vieille)

        except Exception as e:
            self.__logger.exception("Erreur backup")
            info = {'err': str(e)}
            self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_TERMINE, debut_backup, info=info)
            raise e

    def trouver_entete_backup_precedent(self, domaine: str):
        filtre = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: domaine,
            'en-tete.domaine': 'Backup.catalogueHoraire',
            '_evenements.transaction_traitee': {'$exists': True}
        }
        sort_backup = [
            (ConstantesBackup.LIBELLE_HEURE, -1),
            ('_evenements.transaction_traitee', -1)
        ]
        hint = [
            (ConstantesBackup.LIBELLE_HEURE, -1),
            (Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE, 1),
        ]

        collection_backups = self._contexte.document_dao.get_collection(ConstantesBackup.COLLECTION_TRANSACTIONS_NOM)
        plus_recent_backup = collection_backups.find_one(filtre, sort=sort_backup, hint=hint)

        if plus_recent_backup is not None:
            return plus_recent_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]

        return None

    def preparer_sousgroupes_horaires(self, heure: datetime.datetime) -> Dict[str, GroupeSousdomaine]:
        """
        Trouver toutes les transactions disponibles pour un backup. Les grouper par sous-domaine/heure.
        :param heure:
        :return:
        """

        curseur = self._effectuer_requete_domaine(heure)

        # Preparer la liste de tous les sous domaines par heure qui ne sont pas encore dans un backup
        # Calculer taille (nb transactions et groupes) du backup
        groupes_sousdomaine = dict()
        # groupes_sousdomaine_horaire = list()
        for transanter in curseur:
            self.__logger.debug("Vieille transaction : %s" % str(transanter))
            heure_anterieure = pytz.utc.localize(transanter['_id']['timestamp'])
            for sous_domaine_gr in transanter['sousdomaine']:
                # Le sous-domaine est sous forme de liste, le reformuler en chaine sousdomaine.a.b.c
                sous_domaine = '.'.join(sous_domaine_gr)
                information_backup = InformationSousDomaineHoraire(
                    self._nom_collection_transactions, sous_domaine, heure_anterieure,
                    snapshot=False
                )

                try:
                    groupe_sousdomaine = groupes_sousdomaine[sous_domaine]
                except KeyError:
                    groupe_sousdomaine = GroupeSousdomaine()
                    groupes_sousdomaine[sous_domaine] = groupe_sousdomaine

                # Inserer heure dans le groupe. Le tri est fait automatiquement
                groupe_sousdomaine.append(information_backup)

        return groupes_sousdomaine

    def uploader_fichiers_backup(
            self, information_sousgroupe: InformationSousDomaineHoraire, fp_transactions, fp_catalogue, fp_maitrecles):

        self.transmettre_evenement_backup(
            ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_CATALOGUE_PRET, information_sousgroupe.heure)

        catalogue_backup = information_sousgroupe.catalogue_backup

        # Transferer vers consignation_fichier
        data = {
            'timestamp_backup': int(information_sousgroupe.heure.timestamp()),
        }
        try:
            data['fuuid_grosfichiers'] = json.dumps(catalogue_backup['fuuid_grosfichiers']),
        except (KeyError, TypeError):
            pass  # Pas de grosfichiers

        # Preparer URL de connexion a consignationfichiers
        url_consignationfichiers = 'https://%s:%s' % (
            self._contexte.configuration.serveur_consignationfichiers_host,
            self._contexte.configuration.serveur_consignationfichiers_port
        )

        nom_fichier_catalogue = information_sousgroupe.nom_fichier_catalogue
        nom_fichier_transactions = information_sousgroupe.nom_fichier_backup
        files = {
            'transactions': (nom_fichier_transactions, fp_transactions, 'application/x-xz'),
            'catalogue': (nom_fichier_catalogue, fp_catalogue, 'application/x-xz'),
            'cles': ('cles', fp_maitrecles, 'application/x-xz'),
        }

        certfile = self._contexte.configuration.mq_certfile
        keyfile = self._contexte.configuration.mq_keyfile

        # Operation PUT. Note : utilisation methode _requests_put pour permettre hook de unit tests
        r = self._requests_put(
            '%s/backup/domaine/%s' % (url_consignationfichiers, nom_fichier_catalogue),
            data=data,
            files=files,
            verify=self._contexte.configuration.mq_cafile,
            cert=(certfile, keyfile),
            test_params={'information_sousgroupe': information_sousgroupe} # Utilise pour UT
        )

        if r.status_code == 200:
            reponse_json = json.loads(r.text)
            self.__logger.debug("Reponse backup\nHeaders: %s\nData: %s" % (r.headers, str(reponse_json)))

            self.transmettre_evenement_backup(
                ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_UPLOAD_CONFIRME, information_sousgroupe.heure)

            # Verifier si le SHA512 du fichier de backup recu correspond a celui calcule localement
            nom_fichier_transactions = information_sousgroupe.nom_fichier_backup
            if reponse_json.get('ok') is not True:
                erreur = reponse_json.get('err')
                raise ValueError(
                    "Erreur traitement backup. %s" % erreur
                )
        else:
            raise Exception("Reponse %d sur upload backup %s\n"
                            "DETAIL: %s" % (r.status_code, nom_fichier_catalogue, r.text))

    def soumettre_transactions_backup_horaire(self, information_sousgroupe: InformationSousDomaineHoraire):
        """

        :param information_sousgroupe:
        :param reponse:
        :return:
        """

        catalogue_backup = information_sousgroupe.catalogue_backup

        hachage_entete = self.calculer_hash_entetebackup(
            catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE])
        uuid_transaction_catalogue = catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        # Transmettre la transaction au domaine de backup
        # L'enveloppe est deja prete, on fait juste l'emettre
        self._contexte.generateur_transactions.relayer_transaction(catalogue_backup)

        # Marquer les transactions comme inclue dans le backup
        liste_uuids = information_sousgroupe.uuid_transactions
        self.marquer_transactions_backup_complete(self._nom_collection_transactions, liste_uuids)

        transaction_sha512_catalogue = {
            ConstantesBackup.LIBELLE_DOMAINE: information_sousgroupe.sous_domaine,
            # ConstantesBackup.LIBELLE_SECURITE: information_sousgroupe.catalogue_backup[
            #     ConstantesBackup.LIBELLE_SECURITE],
            ConstantesBackup.LIBELLE_HEURE: int(information_sousgroupe.heure.timestamp()),
            ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE: information_sousgroupe.sha512_catalogue,
            ConstantesBackup.LIBELLE_HACHAGE_ENTETE: hachage_entete,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transaction_catalogue,
        }
        self._contexte.generateur_transactions.soumettre_transaction(
            transaction_sha512_catalogue, ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE_HACHAGE)

    def _effectuer_requete_domaine(self, heure: datetime.datetime):
        """
        Requete mongodb pour grouper les transactions par heure.
        :param heure: Timestamp max pour les transactions a trouver
        :return: Curseur de groupes de transactions non sauvegardees dans un backup precedent l'heure en parametre
        """
        # Verifier s'il y a des transactions qui n'ont pas ete traitees avant la periode actuelle
        filtre_verif_transactions_anterieures = {
            '_evenements.transaction_complete': True,
            '_evenements.%s' % Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG: False,
            '_evenements.transaction_traitee': {'$lt': heure},
        }
        regroupement_periode = {
            'year': {'$year': '$_evenements.transaction_traitee'},
            'month': {'$month': '$_evenements.transaction_traitee'},
            'day': {'$dayOfMonth': '$_evenements.transaction_traitee'},
            'hour': {'$hour': '$_evenements.transaction_traitee'},
        }

        # Regroupeemnt par date et par domaine/sous-domaine (l'action est retiree du domaine pour grouper)
        regroupement = {
            '_id': {
                'timestamp': {
                    '$dateFromParts': regroupement_periode
                },
            },
            'sousdomaine': {
                '$addToSet': {
                    '$slice': [
                        {'$split': ['$en-tete.domaine', '.']},
                        {'$add': [{'$size': {'$split': ['$en-tete.domaine', '.']}}, -1]}
                    ]
                }
            },
            'count': {'$sum': 1}
        }
        sort = {
            '_id.timestamp': 1,
            # 'sousdomaine': 1
        }
        operation = [
            {'$match': filtre_verif_transactions_anterieures},
            {'$group': regroupement},
            {'$sort': sort},
        ]
        hint = {
            '_evenements.transaction_traitee': 1,
            '_evenements.transaction_complete': 1,
            '_evenements.%s' % Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG: 1,
        }
        collection_transactions = self._contexte.document_dao.get_collection(self._nom_collection_transactions)

        return collection_transactions.aggregate(operation, hint=hint)

    def _execution_backup_horaire(self, information_sousgroupe: InformationSousDomaineHoraire):

        # Creer repertoire backup (s'assurer qu'il existe)
        Path(information_sousgroupe.backup_workdir).mkdir(mode=0o700, parents=True, exist_ok=True)

        # Effectuer requete sur les transactions a inclure
        curseur = self.preparer_curseur_transactions(
            information_sousgroupe.nom_collection_mongo,
            information_sousgroupe.sous_domaine,
            information_sousgroupe.heure_fin
        )

        # Parcourir le curseur et persister les transactions
        with open(information_sousgroupe.path_fichier_backup, 'wb') as fichier:
            self._persister_transactions_backup(information_sousgroupe, curseur, fichier)

        if len(information_sousgroupe.uuid_transactions) > 0:
            # Calculer SHA512 du fichier de backup des transactions
            information_sousgroupe.sha512_backup = self.calculer_fichier_SHA512(
                information_sousgroupe.path_fichier_backup)

            if information_sousgroupe.transaction_maitredescles is not None:
                # Preparer la transaction maitredescles
                information_sousgroupe.transaction_maitredescles[ConstantesBackup.LIBELLE_HACHAGE_BYTES] = information_sousgroupe.sha512_backup
                information_sousgroupe.path_fichier_maitrecles = 'cles.json.xz'
                with lzma.open(information_sousgroupe.path_fichier_maitrecles, 'wt') as fichier:
                    self.persister_cles(information_sousgroupe, fichier)

            # Sauvegarder catalogue et calculer digest
            with lzma.open(information_sousgroupe.path_fichier_catalogue, 'wt') as fichier:
                self.persister_catalogue(information_sousgroupe, fichier)
            information_sousgroupe.sha512_catalogue = self.calculer_fichier_SHA512(
                information_sousgroupe.path_fichier_backup)

        else:
            self.__logger.debug("Backup: aucune transaction, backup annule")

    def _persister_transactions_backup(self, information_sousgroupe: InformationSousDomaineHoraire, curseur, fp_fichier):
        lzma_compressor = lzma.LZMACompressor()

        # Preparer chiffrage si applicable
        cipher = information_sousgroupe.cipher
        if cipher is not None:
            fp_fichier.write(cipher.start_encrypt())

        for transaction in curseur:
            uuid_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
            try:
                # Extraire metadonnees de la transaction
                info_transaction = self._extraire_certificats(transaction, information_sousgroupe.heure)
                for cle in InformationSousDomaineHoraire.CLES_SET:
                    try:
                        groupe_cles_backup = information_sousgroupe.catalogue_backup[cle]
                    except KeyError:
                        groupe_cles_backup = set()
                        information_sousgroupe.catalogue_backup[cle] = groupe_cles_backup

                    try:
                        cles_transaction = info_transaction[cle]
                        groupe_cles_backup.update(cles_transaction)
                    except KeyError:
                        pass  # OK, group non present dans transaction

                tran_json = json.dumps(transaction, sort_keys=True, ensure_ascii=True, cls=BackupFormatEncoder)
                if information_sousgroupe.cipher is not None:
                    fp_fichier.write(
                        cipher.update(
                            lzma_compressor.compress(tran_json.encode('utf-8'))
                        )
                    )

                    # Une transaction par ligne
                    fp_fichier.write(information_sousgroupe.cipher.update(lzma_compressor.compress(b'\n')))
                else:
                    fp_fichier.write(lzma_compressor.compress(tran_json.encode('utf-8')))

                    # Une transaction par ligne
                    fp_fichier.write(lzma_compressor.compress(b'\n'))

                # La transaction est bonne, on l'ajoute a la liste inclue dans le backup
                information_sousgroupe.uuid_transactions.append(uuid_transaction)
            except HachageInvalide:
                self.__logger.error("Transaction hachage invalide %s: transaction exclue du backup de %s" % (
                    uuid_transaction, information_sousgroupe.nom_collection_mongo))
                # Marquer la transaction comme invalide pour backup
                information_sousgroupe.liste_uuids_invalides.append(uuid_transaction)
            except (CertificatInvalide, CertificatInconnu):
                self.__logger.error("Erreur, certificat de transaction invalide : %s" % uuid_transaction)
                information_sousgroupe.liste_uuids_invalides.append(uuid_transaction)

        if information_sousgroupe.cipher is not None:
            fp_fichier.write(information_sousgroupe.cipher.update(lzma_compressor.flush()))
            fp_fichier.write(information_sousgroupe.cipher.finalize())
        else:
            fp_fichier.write(lzma_compressor.flush())

    def _preparation_backup_horaire(self, information_sousgroupe: InformationSousDomaineHoraire):
        heure = information_sousgroupe.heure
        if information_sousgroupe.snapshot:
            heure_str = heure.strftime("%Y%m%d%H%M") + '-SNAPSHOT'
        else:
            heure_str = heure.strftime("%Y%m%d%H")
        information_sousgroupe.heure_fin = heure + datetime.timedelta(hours=1)

        self.__logger.debug("Backup collection %s entre %s et %s" % (
            information_sousgroupe.nom_collection_mongo, heure, information_sousgroupe.heure_fin))
        prefixe_fichier = information_sousgroupe.sous_domaine

        # Determiner si on doit chiffrer le fichier de transactions
        if self._doit_chiffrer():
            # Fichier va etre chiffre en format mgs1
            extension_transactions = 'jsonl.xz.mgs1'
        else:
            extension_transactions = 'jsonl.xz'

        # Determiner path fichiers
        backup_workdir = self._contexte.configuration.backup_workdir

        backup_nomfichier = '%s_%s.%s' % (
            prefixe_fichier, heure_str, extension_transactions)
        information_sousgroupe.path_fichier_backup = path.join(backup_workdir, backup_nomfichier)

        catalogue_nomfichier = '%s_%s.json.xz' % (prefixe_fichier, heure_str)
        information_sousgroupe.path_fichier_catalogue = path.join(backup_workdir, catalogue_nomfichier)

        # Preparer le contenu du catalogue
        self.preparer_catalogue(information_sousgroupe)

        # Preparer chiffrage, cle
        if self._doit_chiffrer():
            cipher, transaction_maitredescles = self.__backup_util.preparer_cipher(
                information_sousgroupe.catalogue_backup, information_sousgroupe.info_cles,
                heure_str=heure_str, nom_domaine=information_sousgroupe.sous_domaine,
            )

            information_sousgroupe.cipher = cipher
            information_sousgroupe.transaction_maitredescles = transaction_maitredescles

            # Note : il manque le hachage du fichier de backup (transactions), on ne peut pas signer tout de suite
            # # Inserer la transaction de maitre des cles dans l'info backup pour l'uploader avec le PUT
            # self._contexte.generateur_transactions.preparer_enveloppe(
            #     transaction_maitredescles,
            #     Constantes.ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPTRANSACTIONS
            # )

            if information_sousgroupe.snapshot is True:
                # Conserver les cles de backup dans le snapshot - ces cles ne sont pas sauvegardes par le
                # maitre des cles (snapshot est temporaire)
                information_sousgroupe.catalogue_backup['cles'] = transaction_maitredescles['cles']

    def _doit_chiffrer(self):
        """
        :return: True s'il faut chiffrer le fichier de transactions.
        """
        chiffrer_transactions = self.__niveau_securite in [Constantes.SECURITE_PRIVE, Constantes.SECURITE_PROTEGE,
                                                           Constantes.SECURITE_SECURE]

        return chiffrer_transactions

    def persister_cles(self, information_sousgroupe: InformationSousDomaineHoraire, fp_fichier):
        """
        Conserve le fichier de maitre des cles pour upload
        :param information_sousgroupe:
        :param fp_fichier:
        :return:
        """
        cles = information_sousgroupe.transaction_maitredescles

        # Generer l'entete et la signature
        cles_json = json.dumps(cles, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)

        # Recharger le fichier pour avoir le format exact (e.g. encoding dates)
        cles_backup = json.loads(cles_json)
        cles_backup = self._contexte.generateur_transactions.preparer_enveloppe(
            cles_backup,
            '.'.join([
                Constantes.ConstantesMaitreDesCles.DOMAINE_NOM,
                Constantes.ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE,
            ]),
            ajouter_certificats=True
        )

        # Remplacer le catalogue precedent dans information_sousgroupe
        information_sousgroupe.transaction_maitredescles = cles_backup

        # Sauvegarder sur disque
        cles_json = json.dumps(cles_backup, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
        fp_fichier.write(cles_json)

    def persister_catalogue(self, information_sousgroupe: InformationSousDomaineHoraire, fp_fichier_catalogue):
        catalogue_backup = information_sousgroupe.catalogue_backup

        catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE] = information_sousgroupe.sha512_backup
        catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER] = information_sousgroupe.nom_fichier_backup
        # Changer les set() par des list() pour extraire en JSON
        for cle in InformationSousDomaineHoraire.CLES_SET:
            if isinstance(catalogue_backup[cle], set):
                catalogue_backup[cle] = list(catalogue_backup[cle])

        # Generer l'entete et la signature pour le catalogue
        catalogue_json = json.dumps(catalogue_backup, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
        # Recharger le catalogue pour avoir le format exact (e.g. encoding dates)
        catalogue_backup = json.loads(catalogue_json)
        catalogue_backup = self._contexte.generateur_transactions.preparer_enveloppe(
            catalogue_backup, ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE, ajouter_certificats=True)

        # Remplacer le catalogue precedent dans information_sousgroupe
        information_sousgroupe.catalogue_backup = catalogue_backup

        # Sauvegarder sur disque
        catalogue_json = json.dumps(catalogue_backup, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
        fp_fichier_catalogue.write(catalogue_json)

    def preparer_catalogue(self, information_sousgroupe: InformationSousDomaineHoraire):
        catalogue_backup = {
            ConstantesBackup.LIBELLE_DOMAINE: information_sousgroupe.sous_domaine,
            # ConstantesBackup.LIBELLE_SECURITE: self.__niveau_securite,
            ConstantesBackup.LIBELLE_HEURE: information_sousgroupe.heure,

            ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER: information_sousgroupe.nom_fichier_catalogue,
            ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER: information_sousgroupe.nom_fichier_backup,
            # ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE: None,

            # Conserver la liste des certificats racine, intermediaire et noeud necessaires pour
            # verifier toutes les transactions de ce backup
            # ConstantesBackup.LIBELLE_CERTS_RACINE: set(),
            ConstantesBackup.LIBELLE_CERTS_INTERMEDIAIRES: set(),
            ConstantesBackup.LIBELLE_CERTS: set(),
            ConstantesBackup.LIBELLE_CERTS_CHAINE_CATALOGUE: list(),

            # Conserver la liste des grosfichiers requis pour ce backup
            ConstantesBackup.LIBELLE_FUUID_GROSFICHIERS: dict(),

            ConstantesBackup.LIBELLE_BACKUP_PRECEDENT: information_sousgroupe.chainage_backup_precedent,
        }
        information_sousgroupe.catalogue_backup = catalogue_backup

        # Ajouter le certificat du module courant pour etre sur
        clecert_courant = self._contexte.configuration.cle
        enveloppe = EnveloppeCertificat(certificat_pem=clecert_courant.chaine)
        fp_enveloppe = 'sha256_b64:' + enveloppe.fingerprint_sha256_b64

        # Conserver la chaine de validation du catalogue
        certs_pem = {fp_enveloppe: enveloppe.certificat_pem}
        catalogue_backup[ConstantesBackup.LIBELLE_CERTS_PEM] = certs_pem

        liste_enveloppes_cas = enveloppe.chaine_enveloppes()

        certificats_validation_catalogue = list()
        catalogue_backup[ConstantesBackup.LIBELLE_CERTS_CHAINE_CATALOGUE] = certificats_validation_catalogue
        for cert_ca in liste_enveloppes_cas:
            fingerprint_ca = 'sha256_b64:' + cert_ca.fingerprint_sha256_b64
            certificats_validation_catalogue.append(fingerprint_ca)
            certs_pem[fingerprint_ca] = cert_ca.certificat_pem

        if information_sousgroupe.snapshot:
            # Ajouter flag pour indiquer que ce catalogue de backup est un snapshot
            # Les snapshots sont des backups horaires incomplets et volatils
            catalogue_backup['snapshot'] = True

        return catalogue_backup

    def preparer_curseur_transactions(self, nom_collection_mongo, sous_domaine, heure_max: datetime.datetime = None):
        # Format sous-domaine est domaine.action ou domaine.sousdomaine.action
        sous_domaine_regex = '^' + sous_domaine.replace('.', '\\.') + '\\.[A-Za-z0-9_\\/\\-]+$'

        coltrans = self._contexte.document_dao.get_collection(nom_collection_mongo)
        label_tran = '%s.%s' % (
        Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE)
        label_backup = '%s.%s' % (
        Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG)
        filtre = {
            label_tran: True,
            label_backup: False,
            'en-tete.domaine': {'$regex': sous_domaine_regex},
        }
        if heure_max:
            filtre['_evenements.transaction_traitee'] = {'$lt': heure_max}

        sort = [
            ('_evenements.transaction_traitee', 1)
        ]
        hint = [
            ('_evenements.transaction_traitee', 1),
            (label_tran, 1),
            (label_backup, 1),
        ]
        curseur = coltrans.find(filtre, sort=sort, hint=hint)
        return curseur

    def _extraire_certificats(self, transaction, heure: datetime.datetime):
        """
        Verifie la signature de la transaction et extrait les certificats requis pour le backup.

        :param transaction:
        :return:
        """
        # enveloppe_initial = self._contexte.verificateur_transaction.verifier(transaction)
        enveloppe = self._contexte.validateur_message.verifier(
            transaction, utiliser_date_message=True, utiliser_idmg_message=True)

        liste_enveloppes_cas = [enveloppe]
        for cert_pem in enveloppe.reste_chaine_pem:
            liste_enveloppes_cas.append(EnveloppeCertificat(certificat_pem=cert_pem))

        # S'assurer que le certificat racine correspond a la transaction
        ca_racine = liste_enveloppes_cas[-1]
        if ca_racine.fingerprint_base58 != transaction['en-tete']['idmg']:
            raise ValueError("Transaction IDMG ne correspond pas au certificat racine " + enveloppe.fingerprint_base58)

        # Extraire liste de fingerprints
        liste_cas = ['sha256_b64:' + enveloppe.fingerprint_sha256_b64 for enveloppe in liste_enveloppes_cas]

        return {
            'certificats': ['sha256_b64:' + enveloppe.fingerprint_sha256_b64],
            'certificats_intermediaires': liste_cas[1:-1],
            'certificats_millegrille': [liste_cas[-1]],
        }

    def marquer_transactions_backup_complete(self, nom_collection_mongo: str, uuid_transactions: list):
        """
        Marquer une liste de transactions du domaine comme etat inclues dans un backup horaire.

        :param nom_collection_mongo: Nom de la collection des transactions du domaine
        :param uuid_transactions: Liste des uuid de transactions (en-tete)
        :return:
        """
        evenement = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transactions,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_collection_mongo,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_TRANSACTION_BACKUP_HORAIRE_COMPLETE,
        }
        domaine_action = 'evenement.%s.transactionEvenement' % self._nom_domaine
        # self._contexte.message_dao.transmettre_message(evenement, domaine_action)
        self._contexte.generateur_transactions.emettre_message(
            evenement, domaine_action, exchanges=[Constantes.SECURITE_SECURE])

    def marquer_transactions_invalides(self, nom_collection_mongo: str, uuid_transactions: list):
        """
        Effectue une correction sur les transactions considerees invalides pour le backup. Ces transactions
        deja traitees sont dans un etat irrecuperable qui ne permet pas de les valider.

        :param nom_collection_mongo: Nom de la collection des transactions du domaine
        :param uuid_transactions: Liste des uuid de transactions (en-tete)
        :return:
        """

        evenement = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transactions,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_collection_mongo,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_TRANSACTION_BACKUP_ERREUR,
        }
        domaine_action = 'evenement.%s.transactionEvenement' % self._nom_domaine
        self._contexte.generateur_transactions.emettre_message(
            evenement, domaine_action, exchanges=[Constantes.SECURITE_PROTEGE])

    def creer_backup_quoditien(self, domaine: str, jour: datetime.datetime):
        coldocs = self._contexte.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)

        # Calculer la fin du jour comme etant le lendemain, on fait un "<" dans la selection
        jour = datetime.datetime(year=jour.year, month=jour.month, day=jour.day, tzinfo=pytz.UTC)
        fin_jour = jour + datetime.timedelta(days=1)

        # Faire la liste des catalogues de backups qui sont dus
        filtre_backups_quotidiens_dirty = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
            ConstantesBackup.LIBELLE_DOMAINE: {'$regex': '^' + domaine},
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            ConstantesBackup.LIBELLE_JOUR: {'$lt': fin_jour}
        }
        curseur_catalogues = coldocs.find(filtre_backups_quotidiens_dirty)
        plus_vieux_jour = jour

        for catalogue in curseur_catalogues:

            # Identifier le plus vieux backup qui est effectue
            # Utilise pour transmettre trigger backup annuel
            jour_backup = pytz.utc.localize(catalogue[ConstantesBackup.LIBELLE_JOUR])
            if plus_vieux_jour > jour_backup:
                plus_vieux_jour = jour_backup

            # Filtrer catalogue pour retirer les champs Mongo
            for champ in catalogue.copy().keys():
                if champ.startswith('_') or champ in [ConstantesBackup.LIBELLE_DIRTY_FLAG]:
                    del catalogue[champ]

            # Generer l'entete et la signature pour le catalogue
            catalogue_json = json.dumps(catalogue, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
            catalogue = json.loads(catalogue_json)
            catalogue_quotidien = self._contexte.generateur_transactions.preparer_enveloppe(
                catalogue, ConstantesBackup.TRANSACTION_CATALOGUE_QUOTIDIEN, ajouter_certificats=True)
            self.__logger.debug("Catalogue:\n%s" % catalogue_quotidien)

            # Transmettre le catalogue au consignateur de fichiers sous forme de commande. Ceci declenche la
            # creation de l'archive de backup. Une fois termine, le consignateur de fichier va transmettre une
            # transaction de catalogue quotidien.
            self._contexte.generateur_transactions.transmettre_commande(
                {'catalogue': catalogue_quotidien}, ConstantesBackup.COMMANDE_BACKUP_QUOTIDIEN)

        self.transmettre_trigger_annee_precedente(plus_vieux_jour)

    def creer_backup_annuel(self, domaine: str, annee: datetime.datetime):
        coldocs = self._contexte.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)

        annee = datetime.datetime(year=annee.year, month=1, day=1, tzinfo=pytz.UTC)
        # annee_fin = annee.year
        # fin_annee = datetime.datetime(year=annee_fin, month=1, day=1, tzinfo=pytz.UTC)

        # Faire la liste des catalogues de backups qui sont dus
        filtre_backups_annuels_dirty = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_ANNUEL,
            ConstantesBackup.LIBELLE_DOMAINE: {'$regex': '^' + domaine},
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            ConstantesBackup.LIBELLE_ANNEE: {'$lte': annee}
        }
        curseur_catalogues = coldocs.find(filtre_backups_annuels_dirty)
        plus_vieille_annee = annee

        for catalogue in curseur_catalogues:

            # Identifier le plus vieux backup qui est effectue
            # Utilise pour transmettre trigger backup mensuel
            annee_backup = pytz.utc.localize(catalogue[ConstantesBackup.LIBELLE_ANNEE])
            if plus_vieille_annee > annee_backup:
                plus_vieille_annee = annee_backup

            # Filtrer catalogue pour retirer les champs Mongo
            for champ in catalogue.copy().keys():
                if champ.startswith('_') or champ in [ConstantesBackup.LIBELLE_DIRTY_FLAG]:
                    del catalogue[champ]

            # Generer l'entete et la signature pour le catalogue
            catalogue_json = json.dumps(catalogue, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
            catalogue = json.loads(catalogue_json)
            catalogue_annuel = self._contexte.generateur_transactions.preparer_enveloppe(
                catalogue, ConstantesBackup.TRANSACTION_CATALOGUE_ANNUEL, ajouter_certificats=True)
            self.__logger.debug("Catalogue:\n%s" % catalogue_annuel)

            # Transmettre le catalogue au consignateur de fichiers sous forme de commande. Ceci declenche la
            # creation de l'archive de backup. Une fois termine, le consignateur de fichier va transmettre une
            # transaction de catalogue quotidien.
            self._contexte.generateur_transactions.transmettre_commande(
                {'catalogue': catalogue_annuel}, ConstantesBackup.COMMANDE_BACKUP_ANNUEL)

    def transmettre_evenement_backup(self, evenement: str, heure: datetime.datetime, info: dict = None):
        evenement_contenu = {
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: evenement,
            ConstantesBackup.LIBELLE_DOMAINE: self._nom_domaine,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT_TIMESTAMP: int(heure.timestamp()),
            ConstantesBackup.LIBELLE_SECURITE: self.__niveau_securite,
        }
        if info:
            evenement_contenu['info'] = info

        domaine = 'evenement.backup.backupTransaction'

        self._contexte.generateur_transactions.emettre_message(
            evenement_contenu, domaine, exchanges=[Constantes.SECURITE_PROTEGE]
        )

    def transmettre_trigger_jour_precedent(self, heure_plusvieille: datetime.datetime):
        """
        Determiner le jour avant la plus vieille transaction. On va transmettre un declencheur de
        backup quotidien, mensuel et annuel pour les aggregations qui peuvent etre generees

        :param heure_plusvieille:
        :return:
        """

        veille = heure_plusvieille - datetime.timedelta(days=1)
        veille = datetime.datetime(year=veille.year, month=veille.month, day=veille.day, tzinfo=datetime.timezone.utc)
        self.__logger.debug("Veille: %s" % str(veille))

        commande_backup_quotidien = {
            ConstantesBackup.LIBELLE_JOUR: int(veille.timestamp()),
            ConstantesBackup.LIBELLE_DOMAINE: self._nom_domaine,
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_quotidien,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_QUOTIDIEN.replace(
                '_DOMAINE_', self._nom_domaine),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
        )

    def transmettre_trigger_annee_precedente(self, date: datetime.datetime):
        mois_moins_18 = date + datetime.timedelta(days=-549)  # 18 mois
        annee_precedente = datetime.datetime(year=mois_moins_18.year, month=1, day=1, tzinfo=datetime.timezone.utc)

        commande_backup_annuel = {
            ConstantesBackup.LIBELLE_ANNEE: int(annee_precedente.timestamp()),
            ConstantesBackup.LIBELLE_DOMAINE: self._nom_domaine,
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_annuel,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_ANNUEL.replace('_DOMAINE_', self._nom_domaine),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
        )

    def calculer_hash_entetebackup(self, entete):
        """
        Generer une valeur de hachage a partir de l'entete
        :param entete:
        :return:
        """
        hachage_backup = self._contexte.validateur_message.hacher_dict(entete)
        return hachage_backup

    def calculer_fichier_SHA512(self, path_fichier):
        sha512 = hashlib.sha512()
        with open(path_fichier, 'rb') as fichier:
            buffer = fichier.read(HandlerBackupDomaine.BUFFER_SIZE)
            while buffer:
                sha512.update(buffer)
                buffer = fichier.read(HandlerBackupDomaine.BUFFER_SIZE)
        sha512_digest = 'sha512_b64:' + b64encode(sha512.digest()).decode('utf-8')
        return sha512_digest

    def _requests_put(self, *args, **kwargs):
        """
        Hook pour requests.put. Simplifie override pour unit tests.
        """
        if kwargs.get('test_params'):
            del kwargs['test_params']
        return requests.put(*args, **kwargs)


class HandlerRestaurationDomaine:
    """
    Gestionnaire de backup des transactions d'un domaine.
    """

    BUFFER_SIZE = 4 * 1024  # 64 KB

    def __init__(self, contexte, nom_domaine, nom_collection_transactions, nom_collection_documents,
                 niveau_securite=Constantes.SECURITE_PROTEGE):
        self._contexte = contexte
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._nom_domaine = nom_domaine
        self._nom_collection_transactions = nom_collection_transactions
        self._nom_collection_documents = nom_collection_documents
        self.__niveau_securite = niveau_securite
        self.__backup_util = BackupUtil(contexte)

    def restaurer_domaines_horaires(self, nom_collection_mongo):

        url_consignationfichiers = 'https://%s:%s' % (
            self._contexte.configuration.serveur_consignationfichiers_host,
            self._contexte.configuration.serveur_consignationfichiers_port,
        )

        backup_workdir = self._contexte.configuration.backup_workdir
        Path(backup_workdir).mkdir(mode=0o700, parents=True, exist_ok=True)

        data = {
            'domaine': nom_collection_mongo
        }

        with requests.get(
                '%s/backup/liste/backups_horaire' % url_consignationfichiers,
                data=data,
                verify=self._contexte.configuration.mq_cafile,
                cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile)
        ) as r:

            if r.status_code == 200:
                reponse_json = json.loads(r.text)
            else:
                raise Exception("Erreur chargement liste backups horaire")

        self.__logger.debug("Reponse liste backups horaire:\n" + json.dumps(reponse_json, indent=4))

        for heure, backups in reponse_json['backupsHoraire'].items():
            self.__logger.debug("Telechargement fichiers backup %s" % heure)
            path_fichier_transaction = backups['transactions']
            nom_fichier_transaction = path.basename(path_fichier_transaction)

            with requests.get(
                    '%s/backup/horaire/transactions/%s' % (url_consignationfichiers, path_fichier_transaction),
                    verify=self._contexte.configuration.mq_cafile,
                    cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            ) as r:

                r.raise_for_status()

                # Sauvegarder le fichier
                with open(path.join(backup_workdir, nom_fichier_transaction), 'wb') as fichier:
                    for chunk in r.iter_content(chunk_size=8192):
                        fichier.write(chunk)

            path_fichier_catalogue = backups['catalogue']
            nom_fichier_catalogue = path.basename(path_fichier_catalogue)

            # Verifier l'integrite du fichier de transactions
            with lzma.open(path.join(backup_workdir, nom_fichier_catalogue), 'rt') as fichier:
                catalogue = json.load(fichier, object_hook=decoder_backup)

            self.__logger.debug("Verifier signature catalogue %s\n%s" % (nom_fichier_catalogue, catalogue))
            # self._contexte.verificateur_transaction.verifier(catalogue)
            self._contexte.validateur_message.verifier(catalogue, utiliser_date_message=True, utiliser_idmg_message=True)

            with requests.get(
                    '%s/backup/horaire/catalogues/%s' % (url_consignationfichiers, path_fichier_catalogue),
                    verify=self._contexte.configuration.mq_cafile,
                    cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            ) as r:

                r.raise_for_status()

                # Sauvegarder le fichier
                with open(path.join(backup_workdir, nom_fichier_catalogue), 'wb') as fichier:
                    for chunk in r.iter_content(chunk_size=8192):
                        fichier.write(chunk)

                    fichier.flush()

            # Catalogue ok, on verifie fichier de transactions
            self.__logger.debug("Verifier SHA_512 sur le fichier de transactions %s" % nom_fichier_transaction)
            transactions_sha512 = catalogue[ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE]
            sha512 = hashlib.sha512()
            with open(path.join(backup_workdir, nom_fichier_transaction), 'rb') as fichier:
                sha512.update(fichier.read())
            sha512_digest_calcule = 'sha512_b64:' + b64encode(sha512.digest()).decode('utf-8')

            if transactions_sha512 != sha512_digest_calcule:
                raise Exception(
                    "Le fichier de transactions %s est incorrect, SHA512 ne correspond pas a celui du catalogue" %
                    nom_fichier_transaction
                )

        # Une fois tous les fichiers telecharges et verifies, on peut commencer le
        # chargement dans la collection des transactions du domaine

        for heure, backups in reponse_json['backupsHoraire'].items():
            path_fichier_transaction = backups['transactions']
            nom_fichier_transaction = path.basename(path_fichier_transaction)

            with lzma.open(path.join(backup_workdir, nom_fichier_transaction), 'rt') as fichier:
                for transaction in fichier:
                    self.__logger.debug("Chargement transaction restauree vers collection:\n%s" % str(transaction))
                    # Emettre chaque transaction vers le consignateur de transaction
                    self._contexte.generateur_transactions.restaurer_transaction(transaction)


class WrapperDownload(RawIOBase):
    """
    Simule un IOBase pour lecture d'un stream http response (requests)
    """

    def __init__(self, generator):
        super().__init__()
        self.__generator = generator

    def read(self, *args, **kwargs):  # real signature unknown
        for data in self.__generator:
            return data

    def readable(self, *args, **kwargs):  # real signature unknown
        """ Returns True if the IO object can be read. """
        return True


class ReceptionMessage(TraitementMessageCallback):

    def __init__(self, backup_parser, message_dao, configuration):
        super().__init__(message_dao, configuration)
        self.__parser = backup_parser

    def traiter_message(self, ch, method, properties, body):
        message_dict = json.loads(body)
        self.__parser.nouveau_message(message_dict)


class RapportRestauration:

    def __init__(self):
        self.__domaines = set()
        self.__completees_par_domaine = dict()

        # Erreurs catalogues ou fichiers transactions
        self.__digest_transactions_invalide = dict()
        self.__autres_erreurs_par_domaine = dict()
        self.__indechiffrables_par_domaine = dict()

    def incrementer_completee(self, domaine):
        self.incrementer(domaine, self.__completees_par_domaine)

    def incrementer_indechiffrables(self, domaine):
        self.incrementer(domaine, self.__indechiffrables_par_domaine)

    def incrementer_autres_erreurs_par_domaine(self, domaine):
        self.incrementer(domaine, self.__autres_erreurs_par_domaine)

    def incrementer_digest_invalide(self, domaine):
        self.incrementer(domaine, self.__digest_transactions_invalide)

    def incrementer(self, domaine, dictionnaire: dict):
        self.__domaines.add(domaine)
        compteur_domaine = dictionnaire.get(domaine) or 0
        dictionnaire[domaine] = compteur_domaine + 1

    def comptes_domaine(self, domaine):
        info = dict()
        dicts = [
            ('completees', self.__completees_par_domaine),
            ('invalides', self.__digest_transactions_invalide),
            ('erreurs', self.__autres_erreurs_par_domaine),
            ('indechiffrables', self.__indechiffrables_par_domaine),
        ]
        for d in dicts:
            try:
                info[d[0]] = d[1][domaine]
            except(KeyError, IndexError):
                pass

        return info

    def generer_transaction_restauration(self, generateur_transactions):
        transaction = {
            'domaines': list(self.__domaines),
            # 'completees': self.__completees_par_domaine,
            # 'indechiffrables': self.__indechiffrables_par_domaine,
            # 'erreurs': self.__autres_erreurs_par_domaine,
        }

        comptes = list()
        for domaine in self.__domaines:
            info_domaine = self.comptes_domaine(domaine)
            info_domaine['domaine'] = domaine
            comptes.append(info_domaine)

        transaction['comptes'] = comptes

        domaine_action = ConstantesBackup.TRANSACTION_RAPPORT_RESTAURATION
        generateur_transactions.soumettre_transaction(transaction, domaine_action)


class ArchivesBackupParser:
    """
    Parse le fichier .tar transmis par consignationfichiers contenant toutes les archives de backup.
    """

    def __init__(self, contexte: ContexteRessourcesMilleGrilles):
        self.__contexte = contexte
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__path_output: Optional[str] = None
        self._catalogue_horaire_courant = None
        self.__channel = None
        self.__nom_queue: Optional[str] = None
        self.__thread: Optional[Thread] = None
        self.__tar_stream: Optional[tarfile.TarFile] = None
        self.__reponse_cle: Optional[dict] = None
        self.__cle_iv_transactions: Optional[dict] = None

        self.__handler_messages = ReceptionMessage(self, contexte.message_dao, contexte.configuration)

        self.__event_execution = Event()
        self.__event_attente_reponse = Event()

        self.__chaine_pem_courante = contexte.signateur_transactions.chaine_certs

        # Statistiques de restauration, erreurs, etc
        self.__rapport_restauration = RapportRestauration()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def start(self, stream, path_output: str = None) -> Event:
        """
        Demarre execution
        :return: Event qui est set() a la fin de l'execution
        """
        self.__path_output = path_output
        wrapper = WrapperDownload(stream)
        self.__tar_stream = tarfile.open(fileobj=wrapper, mode='r|', debug=3, errorlevel=3)

        self.__thread = Thread(name="ArchivesBackupParser", target=self.parse_tar_stream, daemon=True)
        self.__contexte.message_dao.register_channel_listener(self)

        return self.__event_execution

    def stop(self):
        self.__logger.debug("Stop")
        self.__event_execution.set()
        if self.__channel is not None:
            self.__channel.close()

    def on_channel_open(self, channel):
        self.__logger.debug("Channel open")
        channel.basic_qos(prefetch_count=10)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel

        self.__channel.queue_declare(
            queue='',
            callback=self.q_ouverte,
        )

    def on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.__logger.info("MQ Channel ferme code=%s, reason=%s" % (code, reason))

    def q_ouverte(self, queue):
        self.__nom_queue = queue.method.queue
        self.__channel.basic_consume(self.__handler_messages.callbackAvecAck, queue=self.__nom_queue, no_ack=False)
        self.__thread.start()

    def nouveau_message(self, message_dict):
        self.__logger.debug("Message cle de backup recu : %s", message_dict)
        self.__reponse_cle = message_dict

        try:
            self.__cle_iv_transactions = {
                'cle': message_dict['cle'],
                'iv': message_dict['iv'],
            }
        finally:
            self.__event_attente_reponse.set()

    def parse_tar_stream(self):
        try:
            for tar_info in self.__tar_stream:
                self._process_tar_info(tar_info)
        finally:
            self.__rapport_restauration.generer_transaction_restauration(self.__contexte.generateur_transactions)
            self.__event_execution.wait(1)
            self.stop()

    def _process_tar_info(self, tar_info):
        path_fichier = tar_info.name

        type_archive = self.detecter_type_archive(path_fichier)
        nom_fichier = path.basename(path_fichier)

        tar_fo = self.__tar_stream.extractfile(tar_info)
        if self.__path_output is not None:
            path_local = path.join(self.__path_output, nom_fichier)
            with open(path_local,  'wb') as fichier:
                fichier.write(tar_fo.read())
            try:
                with open(path_local, 'rb') as fichier:
                    self.__traiter_archive(type_archive, nom_fichier, fichier)
            except:
                self.__logger.exception("Erreur traitement archive top level")
        else:
            # Lecture directe du stream tar sans fichier local
            self.__traiter_archive(type_archive, nom_fichier, tar_fo)

    def __traiter_archive(self, type_archive, nom_fichier, file_object):
        if type_archive == 'tar':
            self._process_archive_aggregee(file_object)
        elif type_archive == 'snapshot_catalogue':
            self._process_archive_snapshot_catalogue(nom_fichier, file_object)
        elif type_archive == 'snapshot_transactions':
            self._process_archive_snapshot_transaction(nom_fichier, file_object)
        elif type_archive == 'catalogue':
            self._process_archive_horaire_catalogue(nom_fichier, file_object)
        elif type_archive == 'transactions':
            self._process_archive_horaire_transaction(nom_fichier, file_object)
        elif type_archive == 'grosfichier':
            pass  # Skip les fichiers
        else:
            raise TypeArchiveInconnue(type_archive)

    def _process_archive_aggregee(self, file_object):
        self.__logger.debug("Traitement archive annuelle/quotidienne")
        try:
            tar_aggregee = tarfile.open(fileobj=file_object, mode='r|')
            self.__logger.debug("Liste contenu archive annuelle/quotidienne")

            for tarinfo_aggrege in tar_aggregee:
                path_fichier = tarinfo_aggrege.name
                fo = tar_aggregee.extractfile(tarinfo_aggrege)
                try:
                    type_archive = self.detecter_type_archive(path_fichier)
                    nom_fichier = path.basename(path_fichier)
                    self.__traiter_archive(type_archive, nom_fichier, fo)
                except TypeArchiveInconnue:
                    self.__logger.exception("Type d'archive inconnue, on skip")
                    fo.read()  # Skip fichier complet

        except ValueError:
            self.__logger.exception("Erreur lecture archive quotidienne")

    def _process_archive_horaire_catalogue(self, nom_fichier: str, file_object):
        # self.__logger.debug("Catalogue horaire")
        catalogue_json = self._extract_catalogue(nom_fichier, file_object)
        self.__logger.debug("Catalogue horaire : %s" % catalogue_json)
        generateur = self.__contexte.generateur_transactions
        generateur.emettre_message(catalogue_json, 'commande.transaction.restaurerTransaction', exchanges=[Constantes.SECURITE_SECURE])
        self._catalogue_horaire_courant = catalogue_json

    def _process_archive_horaire_transaction(self, nom_fichier: str, file_object):
        self.__logger.debug("Transactions horaire")
        self._extract_transaction(nom_fichier, file_object)

    def _process_archive_snapshot_catalogue(self, nom_fichier: str, file_object):
        # self.__logger.debug("Catalogue snapshot")
        catalogue_json = self._extract_catalogue(nom_fichier, file_object)
        self.__logger.debug("Catalogue snapshot : %s" % catalogue_json)
        self._catalogue_horaire_courant = catalogue_json

    def _process_archive_snapshot_transaction(self, nom_fichier: str, file_object):
        self.__logger.debug("Transactions snapshot")
        self._extract_transaction(nom_fichier, file_object)

    def _extract_catalogue(self, nom_fichier, file_object):
        try:
            lzma_file_object = LZMAFile(file_object)
            archive_json = json.load(lzma_file_object)

            # Si transactions chiffrees, demander cle
            if archive_json.get('iv'):
                info_cle = self.demander_cle(archive_json)
                self.__logger.debug("Reponse commande submit catalogue : %s" % info_cle)

            return archive_json
        except json.decoder.JSONDecodeError:
            self.__logger.warning("Erreur traitement catalogue %s" % nom_fichier)

    def _extract_transaction(self, nom_fichier, file_object):
        self.__logger.debug("Extract transactions %s", nom_fichier)
        catalogue = self._catalogue_horaire_courant
        domaine = catalogue['domaine']

        try:
            extension = path.splitext(nom_fichier)

            if extension[1] == '.mgs1':
                # Transaction chiffree, demander la cle pour dechiffrer
                internal_file_object = None

                try:
                    iv = b64decode(self.__cle_iv_transactions['iv'].encode('utf-8'))
                    cle = self.__cle_iv_transactions['cle']

                    cle_dechiffree = self.__contexte.signateur_transactions.dechiffrage_asymmetrique(cle)
                    decipher = CipherMsg1Dechiffrer(iv, cle_dechiffree)
                    stream = DecipherStream(decipher, file_object)

                    # Wrapper le stream dans un decodeur lzma
                    internal_file_object = LZMAFile(stream)

                except (KeyError, TypeError):
                    self.__logger.warning("Fichier transaction, cle non dechiffrable")
                    self.__rapport_restauration.incrementer_indechiffrables(domaine)

            else:
                # Note : pas de dechiffrage, juste le calcul du digest
                stream = DigestStream(file_object)
                internal_file_object = LZMAFile(stream)

            if internal_file_object is not None:
                generateur = self.__contexte.generateur_transactions
                try:
                    for line in internal_file_object:
                        archive_json = json.loads(line.decode('utf-8'))
                        self.__logger.debug("Transaction : %s" % archive_json)
                        generateur.emettre_message(archive_json, 'commande.transaction.restaurerTransaction', exchanges=[Constantes.SECURITE_SECURE])

                    digest_transactions = stream.digest()
                    digest_transactions_catalogue = catalogue[ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE]
                    if digest_transactions == digest_transactions_catalogue:
                        self.__logger.debug("Digest calcule du fichier de transaction est OK : %s", digest_transactions)
                    else:
                        self.__logger.warning("Digest calcule du fichier de transaction est invalide : %s", digest_transactions)
                        self.__rapport_restauration.incrementer_digest_invalide(domaine)
                except EOFError as e:
                    self.__logger.warning("Erreur - EOF : %s" % str(e))

            self.__rapport_restauration.incrementer_completee(domaine)

        except (json.decoder.JSONDecodeError, LZMAError) as e:
            self.__logger.exception("Erreur traitement transactions %s : %s" % (nom_fichier, str(e)))
            self.__rapport_restauration.incrementer_autres_erreurs_par_domaine(domaine)
        # finally:
        #     # S'assurer que le fichier a ete lu au complet (en cas d'erreur)
        #     file_object.read()

    def detecter_type_archive(self, path_fichier):
        # Determiner type d'archive - annuelle, quotidienne, horaire ou snapshot
        nom_fichier = path.basename(path_fichier)

        # Detecter grosfichier par le repertoire
        dernier_folder = path.basename(path.dirname(path_fichier))
        if dernier_folder == 'grosfichiers':
            return 'grosfichier'

        # Detecter type de fichier en fonction de l'extension
        # .tar = agregee (quotidienne ou annuelle)
        # .jsonl.xz.mgs1, .jsonl.xz = transactions
        # .json.xz = catalogue

        if nom_fichier.endswith('.tar'):
            return 'tar'
        elif nom_fichier.endswith('.json1.xz.mgs1') or nom_fichier.endswith('.jsonl.xz'):
            type = 'transactions'
        elif nom_fichier.endswith('.json.xz'):
            type = 'catalogue'
        else:
            raise TypeArchiveInconnue("Type archive inconnue : %s" % nom_fichier)

        # Determiner le sous_type "snapshot"
        try:
            nom_fichier.index('SNAPSHOT')
        except ValueError:
            return type
        else:
            return 'snapshot_' + type

    def demander_cle(self, catalogue):

        # Effacer la reponse de la demande precedente, resetter event d'attente
        self.__reponse_cle = None
        self.__cle_iv_transactions = None
        self.__event_attente_reponse.clear()

        # Produire la requete, include la cle/iv du catalogue pour dechiffrage en ligne si possible
        # Noter que la requete va permettre de conserver la cle cote serveur si elle n'est pas connue
        domaine_action = Constantes.ConstantesMaitreDesCles.DOMAINE_NOM + '.' + Constantes.ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE_BACKUP
        requete = {
            'certificat': self.__chaine_pem_courante ,
            'domaine': catalogue[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE],
            'identificateurs_document': {
                'transactions_nomfichier': catalogue[ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER],
            },
            "iv": catalogue['iv'],
        }
        try:
            requete['cle'] = catalogue['cle']
        except KeyError:
            pass
        try:
            requete['cles'] = catalogue['cles']
        except KeyError:
            pass

        # Demander la cle rechiffree - il est possible que la cle soit inconnue, la requete va automatiquement
        # la conserver pour le prochein rechiffrage avec cle de backup ou cle de millegrille
        self.__contexte.generateur_transactions.transmettre_requete(
            requete, domaine_action, correlation_id='cle', reply_to=self.__nom_queue)

        self.__logger.debug("Attendre reponse cle")
        self.__event_attente_reponse.wait(1)
        if self.__event_attente_reponse.is_set():
            self.__logger.debug("Reponse recue")
        self.__event_attente_reponse.clear()

        return self.__reponse_cle


class TypeArchiveInconnue(Exception):
    """
    Lancee durant la restauration si une archive ne peut pas etre traitee a cause du type.
    """
    pass


class BackupException(Exception):
    """
    Exception generique lancee durant un Backup
    """
    pass

import logging
import datetime
import pytz
import json
import lzma
import hashlib
import requests
import tarfile

from typing import Optional
from io import RawIOBase
from os import path
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
from lzma import LZMAFile, LZMAError
from threading import Thread, Event

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup
from millegrilles.util.JSONMessageEncoders import BackupFormatEncoder, DateFormatEncoder, decoder_backup
from millegrilles.SecuritePKI import HachageInvalide, CertificatInvalide, CertificatInconnu, AutorisationConditionnelleDomaine
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


class BackupUtil:

    def __init__(self, contexte):
        self.__contexte = contexte
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def preparer_cipher(self, catalogue_backup, info_cles: dict, nom_domaine: str = None, nom_application: str = None, output_stream=None):
        """
        Prepare un objet cipher pour chiffrer le fichier de transactions

        :param catalogue_backup:
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

        identificateurs_document = dict()
        liste_identificateurs = [
            ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER,
            ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER,
        ]
        for ident in liste_identificateurs:
            try:
                identificateurs_document[ident] = catalogue_backup[ident]
            except KeyError:
                pass

        transaction_maitredescles = {
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateurs_document,
            'iv': iv,
            'cles': cles_chiffrees,
        }
        if nom_domaine is not None:
            transaction_maitredescles['domaine'] = nom_domaine
        if nom_application is not None:
            transaction_maitredescles['application'] = nom_application

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

    def __init__(self, contexte, nom_domaine, nom_collection_transactions, nom_collection_documents,
                 niveau_securite=Constantes.SECURITE_PROTEGE):
        self._contexte = contexte
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._nom_domaine = nom_domaine
        self._nom_collection_transactions = nom_collection_transactions
        self._nom_collection_documents = nom_collection_documents
        self.__niveau_securite = niveau_securite
        self.__backup_util = BackupUtil(contexte)

    def backup_domaine(self, heure: datetime.datetime, entete_backup_precedent: dict, info_cles: dict):
        """

        :param heure: Heure du backup horaire
        :param entete_backup_precedent: Entete du catalogue precedent, sert a creer une chaine de backups (merkle tree)
        :param info_cles: Reponse de requete ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        :return:
        """
        debut_backup = heure

        self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_DEBUT, debut_backup)

        curseur = self._effectuer_requete_domaine(heure)

        try:
            # Utilise pour creer une chaine entre backups horaires
            chainage_backup_precedent = None
            if entete_backup_precedent:
                chainage_backup_precedent = {
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: entete_backup_precedent[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
                    ConstantesBackup.LIBELLE_HACHAGE_ENTETE: self.calculer_hash_entetebackup(entete_backup_precedent)
                }

            heures_sous_domaines = dict()

            heure_plusvieille = heure

            for transanter in curseur:
                self.__logger.debug("Vieille transaction : %s" % str(transanter))
                heure_anterieure = pytz.utc.localize(transanter['_id']['timestamp'])
                for sous_domaine_gr in transanter['sousdomaine']:
                    sous_domaine = '.'.join(sous_domaine_gr)

                    # Conserver l'heure la plus vieille dans ce backup
                    # Permet de declencher backup quotidiens anterieurs
                    heure_plusvieille = heures_sous_domaines.get(sous_domaine)
                    if heure_plusvieille is None or heure_plusvieille > heure_anterieure:
                        heure_plusvieille = heure_anterieure
                        heures_sous_domaines[sous_domaine] = heure_anterieure

                    # Creer le fichier de backup
                    dependances_backup = self._backup_horaire_domaine(
                        self._nom_collection_transactions,
                        sous_domaine,
                        heure_anterieure,
                        chainage_backup_precedent,
                        info_cles
                    )

                    catalogue_backup = dependances_backup.get('catalogue')
                    if catalogue_backup is not None:
                        self.transmettre_evenement_backup(
                            ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_CATALOGUE_PRET, debut_backup)

                        hachage_entete = self.calculer_hash_entetebackup(catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE])
                        uuid_transaction_catalogue = catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

                        path_fichier_transactions = dependances_backup['path_fichier_backup']
                        nom_fichier_transactions = path.basename(path_fichier_transactions)

                        path_fichier_catalogue = dependances_backup['path_catalogue']
                        nom_fichier_catalogue = path.basename(path_fichier_catalogue)

                        self.__logger.debug("Information fichier backup:\n%s" % json.dumps(dependances_backup, indent=4, cls=BackupFormatEncoder))

                        # Transferer vers consignation_fichier
                        data = {
                            'timestamp_backup': int(heure_anterieure.timestamp()),
                            'fuuid_grosfichiers': json.dumps(catalogue_backup['fuuid_grosfichiers']),
                        }
                        transaction_maitredescles = dependances_backup.get('transaction_maitredescles')
                        if transaction_maitredescles is not None:
                            data['transaction_maitredescles'] = json.dumps(transaction_maitredescles)

                        # Preparer URL de connexion a consignationfichiers
                        url_consignationfichiers = 'https://%s:%s' % (
                            self._contexte.configuration.serveur_consignationfichiers_host,
                            self._contexte.configuration.serveur_consignationfichiers_port
                        )

                        with open(path_fichier_transactions, 'rb') as transactions_fichier:
                            with open(path_fichier_catalogue, 'rb') as catalogue_fichier:
                                files = {
                                    'transactions': (nom_fichier_transactions, transactions_fichier, 'application/x-xz'),
                                    'catalogue': (nom_fichier_catalogue, catalogue_fichier, 'application/x-xz'),
                                }

                                certfile = self._contexte.configuration.mq_certfile
                                keyfile = self._contexte.configuration.mq_keyfile

                                r = requests.put(
                                    '%s/backup/domaine/%s' % (url_consignationfichiers, nom_fichier_catalogue),
                                    data=data,
                                    files=files,
                                    verify=self._contexte.configuration.mq_cafile,
                                    cert=(certfile, keyfile)
                                )

                        if r.status_code == 200:
                            self.transmettre_evenement_backup(
                                ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_UPLOAD_CONFIRME, debut_backup)

                            reponse_json = json.loads(r.text)
                            self.__logger.debug("Reponse backup\nHeaders: %s\nData: %s" % (r.headers, str(reponse_json)))

                            # Verifier si le SHA512 du fichier de backup recu correspond a celui calcule localement
                            if reponse_json['fichiersDomaines'][nom_fichier_transactions] != \
                                    catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE]:
                                raise ValueError(
                                    "Le SHA512 du fichier de backup de transactions ne correspond pas a celui recu de consignationfichiers")

                            # Transmettre la transaction au domaine de backup
                            # L'enveloppe est deja prete, on fait juste l'emettre
                            self._contexte.message_dao.transmettre_nouvelle_transaction(catalogue_backup, None, None)

                            # Marquer les transactions comme inclue dans le backup
                            liste_uuids = dependances_backup['uuid_transactions']
                            self.marquer_transactions_backup_complete(self._nom_collection_transactions, liste_uuids)

                            transaction_sha512_catalogue = {
                                ConstantesBackup.LIBELLE_DOMAINE: sous_domaine,
                                ConstantesBackup.LIBELLE_SECURITE: dependances_backup['catalogue'][ConstantesBackup.LIBELLE_SECURITE],
                                ConstantesBackup.LIBELLE_HEURE: int(heure_anterieure.timestamp()),
                                ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE: dependances_backup[ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE],
                                ConstantesBackup.LIBELLE_HACHAGE_ENTETE: hachage_entete,
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transaction_catalogue,
                            }

                            self._contexte.generateur_transactions.soumettre_transaction(
                                transaction_sha512_catalogue, ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE_HACHAGE)

                        else:
                            raise Exception("Reponse %d sur upload backup %s" % (r.status_code, nom_fichier_catalogue))

                        # Calculer nouvelle entete
                        entete_backup_precedent = catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
                        chainage_backup_precedent = {
                            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: entete_backup_precedent[
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
                            ConstantesBackup.LIBELLE_HACHAGE_ENTETE: hachage_entete
                        }

                    else:
                        self.__logger.warning(
                            "Aucune transaction valide inclue dans le backup de %s a %s mais transactions en erreur presentes" % (
                                self._nom_collection_transactions, str(heure_anterieure))
                        )

                    # Traiter les transactions invalides
                    liste_uuids_invalides = dependances_backup.get('liste_uuids_invalides')
                    if liste_uuids_invalides and len(liste_uuids_invalides) > 0:
                        self.__logger.error(
                            "Marquer %d transactions invalides exclue du backup de %s a %s" % (
                                len(liste_uuids_invalides), self._nom_collection_transactions, str(heure_anterieure))
                        )
                        self.marquer_transactions_invalides(self._nom_collection_transactions, liste_uuids_invalides)

            self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_TERMINE, debut_backup)

            self.transmettre_trigger_jour_precedent(heure_plusvieille)

        except Exception as e:
            self.__logger.exception("Erreur backup")
            info = {'err': str(e)}
            self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_HORAIRE_TERMINE, debut_backup, info=info)
            raise e

    def backup_snapshot(self, entete_backup_precedent: dict, info_cles: dict):
        """

        :param entete_backup_precedent: Entete du catalogue precedent, sert a creer une chaine de backups (merkle tree)
        :param info_cles: Reponse de requete ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        :return:
        """
        debut_backup = datetime.datetime.utcnow()

        self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_SNAPSHOT_DEBUT, debut_backup)

        curseur = self._effectuer_requete_domaine(debut_backup)

        # Utilise pour creer une chaine entre backups horaires
        chainage_backup_precedent = None
        if entete_backup_precedent:
            chainage_backup_precedent = {
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: entete_backup_precedent[
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
                ConstantesBackup.LIBELLE_HACHAGE_ENTETE: self.calculer_hash_entetebackup(entete_backup_precedent)
            }

        #SNAP heures_sous_domaines = dict()
        heure_backup = datetime.datetime.utcnow()

        try:

            for transanter in curseur:
                self.__logger.debug("Vieille transaction : %s" % str(transanter))
                # SNAP heure_anterieure = pytz.utc.localize(transanter['_id']['timestamp'])
                for sous_domaine_gr in transanter['sousdomaine']:
                    sous_domaine = '.'.join(sous_domaine_gr)

                    # Conserver l'heure la plus vieille dans ce backup
                    # Permet de declencher backup quotidiens anterieurs
                    # SNAP heure_plusvieille = heures_sous_domaines.get(sous_domaine)
                    # SNAP if heure_plusvieille is None or heure_plusvieille > heure_anterieure:
                    # SNAP     heure_plusvieille = heure_anterieure
                    # SNAP     heures_sous_domaines[sous_domaine] = heure_anterieure

                    # Creer le fichier de backup
                    dependances_backup = self._backup_horaire_domaine(
                        self._nom_collection_transactions,
                        sous_domaine,
                        heure_backup,
                        chainage_backup_precedent,
                        info_cles,
                        snapshot=True
                    )

                    catalogue_backup = dependances_backup.get('catalogue')
                    if catalogue_backup is not None:
                        self.transmettre_evenement_backup(
                            ConstantesBackup.EVENEMENT_BACKUP_SNAPSHOT_CATALOGUE_PRET, debut_backup)

                        hachage_entete = self.calculer_hash_entetebackup(
                            catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE])
                        uuid_transaction_catalogue = catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

                        path_fichier_transactions = dependances_backup['path_fichier_backup']
                        nom_fichier_transactions = path.basename(path_fichier_transactions)

                        path_fichier_catalogue = dependances_backup['path_catalogue']
                        nom_fichier_catalogue = path.basename(path_fichier_catalogue)

                        self.__logger.debug("Information fichier backup:\n%s" % json.dumps(dependances_backup, indent=4,
                                                                                           cls=BackupFormatEncoder))

                        # Transferer vers consignation_fichier
                        data = {
                            'timestamp_backup': int(heure_backup.timestamp()),
                            'fuuid_grosfichiers': json.dumps(catalogue_backup['fuuid_grosfichiers']),
                        }

                        # Preparer URL de connexion a consignationfichiers
                        url_consignationfichiers = 'https://%s:%s' % (
                            self._contexte.configuration.serveur_consignationfichiers_host,
                            self._contexte.configuration.serveur_consignationfichiers_port
                        )

                        with open(path_fichier_transactions, 'rb') as transactions_fichier:
                            with open(path_fichier_catalogue, 'rb') as catalogue_fichier:
                                files = {
                                    'transactions': (nom_fichier_transactions, transactions_fichier, 'application/x-xz'),
                                    'catalogue': (nom_fichier_catalogue, catalogue_fichier, 'application/x-xz'),
                                }

                                certfile = self._contexte.configuration.mq_certfile
                                keyfile = self._contexte.configuration.mq_keyfile

                                r = requests.put(
                                    '%s/backup/domaine/%s' % (url_consignationfichiers, nom_fichier_catalogue),
                                    data=data,
                                    files=files,
                                    verify=self._contexte.configuration.mq_cafile,
                                    cert=(certfile, keyfile)
                                )

                        if r.status_code == 200:
                            self.transmettre_evenement_backup(
                                ConstantesBackup.EVENEMENT_BACKUP_SNAPSHOT_UPLOAD_CONFIRME, debut_backup)

                            reponse_json = json.loads(r.text)
                            self.__logger.debug("Reponse backup\nHeaders: %s\nData: %s" % (r.headers, str(reponse_json)))

                            # Verifier si le SHA512 du fichier de backup recu correspond a celui calcule localement
                            if reponse_json['fichiersDomaines'][nom_fichier_transactions] != \
                                    catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE]:
                                raise ValueError(
                                    "Le hachage du fichier de backup de transactions ne correspond pas a celui recu de consignationfichiers")

                        else:
                            raise Exception("Reponse %d sur upload backup %s" % (r.status_code, nom_fichier_catalogue))

                        # Calculer nouvelle entete
                        entete_backup_precedent = catalogue_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
                        chainage_backup_precedent = {
                            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: entete_backup_precedent[
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
                            ConstantesBackup.LIBELLE_HACHAGE_ENTETE: hachage_entete
                        }

                    else:
                        self.__logger.warning(
                            "Aucune transaction valide inclue dans le backup snapshot de %s a %s mais transactions en erreur presentes" % (
                                self._nom_collection_transactions, str(heure_backup))
                        )

            self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_SNAPSHOT_TERMINE, debut_backup)
        except Exception as e:
            self.__logger.exception("Erreur traitement backup")
            info = {'err': str(e)}
            self.transmettre_evenement_backup(ConstantesBackup.EVENEMENT_BACKUP_SNAPSHOT_TERMINE, debut_backup, info=info)

    def _effectuer_requete_domaine(self, heure: datetime.datetime):
        # Verifier s'il y a des transactions qui n'ont pas ete traitees avant la periode actuelle
        idmg = self._contexte.idmg

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
            }
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

    def _backup_horaire_domaine(self, nom_collection_mongo: str, sous_domaine: str, heure: datetime,
                                chainage_backup_precedent: dict,
                                info_cles: dict, snapshot=False) -> dict:
        if snapshot:
            heure_str = heure.strftime("%Y%m%d%H%M") + '-SNAPSHOT'
        else:
            heure_str = heure.strftime("%Y%m%d%H")

        heure_fin = heure + datetime.timedelta(hours=1)
        self.__logger.debug("Backup collection %s entre %s et %s" % (nom_collection_mongo, heure, heure_fin))

        prefixe_fichier = sous_domaine

        curseur = self.preparer_curseur_transactions(nom_collection_mongo, sous_domaine, heure_fin)

        # Creer repertoire backup et determiner path fichier
        backup_workdir = self._contexte.configuration.backup_workdir
        Path(backup_workdir).mkdir(mode=0o700, parents=True, exist_ok=True)

        # Determiner si on doit chiffrer le fichier de transactions
        chiffrer_transactions = self.__niveau_securite in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]

        # Nom fichier transactions avec .jsonl, indique que chaque ligne est un message JSON
        if chiffrer_transactions:
            # Fichier va etre chiffre en format mgs1
            extension_transactions = 'jsonl.xz.mgs1'
        else:
            extension_transactions = 'jsonl.xz'

        backup_nomfichier = '%s_transactions_%s_%s.%s' % (prefixe_fichier, heure_str, self.__niveau_securite, extension_transactions)
        path_fichier_backup = path.join(backup_workdir, backup_nomfichier)

        catalogue_nomfichier = '%s_catalogue_%s_%s.json.xz' % (prefixe_fichier, heure_str, self.__niveau_securite)

        catalogue_backup = self.preparer_catalogue(backup_nomfichier, catalogue_nomfichier, chainage_backup_precedent,
                                                   heure, sous_domaine)

        if snapshot:
            # Ajouter flag pour indiquer que ce catalogue de backup est un snapshot
            # Les snapshots sont des backups horaires incomplets et volatils
            catalogue_backup['snapshot'] = True

        liste_uuid_transactions = list()
        liste_uuids_invalides = list()
        info_backup = {
            'path_fichier_backup': path_fichier_backup,
            'uuid_transactions': liste_uuid_transactions,
            'liste_uuids_invalides': liste_uuids_invalides,
        }

        cles_set = ['certificats_racine', 'certificats_intermediaires', 'certificats', 'fuuid_grosfichiers']

        # Preparer chiffrage, cle
        if chiffrer_transactions:
            cipher, transaction_maitredescles = self.__backup_util.preparer_cipher(catalogue_backup, info_cles, self._nom_domaine)

            # Inserer la transaction de maitre des cles dans l'info backup pour l'uploader avec le PUT
            info_backup['transaction_maitredescles'] = self._contexte.generateur_transactions.preparer_enveloppe(
                transaction_maitredescles,
                Constantes.ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPTRANSACTIONS
            )

            if snapshot is True:
                catalogue_backup['cles'] = transaction_maitredescles['cles']

        else:
            # Pas de chiffrage
            cipher = None

        with open(path_fichier_backup, 'wb') as fichier:
            lzma_compressor = lzma.LZMACompressor()

            # if cipher is not None:
            #     fichier.write(cipher.start_encrypt())

            for transaction in curseur:
                uuid_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                try:
                    # Extraire metadonnees de la transaction
                    info_transaction = self._traiter_transaction(transaction, heure)
                    for cle in cles_set:
                        try:
                            catalogue_backup[cle].update(info_transaction[cle])
                        except KeyError:
                            pass

                    tran_json = json.dumps(transaction, sort_keys=True, ensure_ascii=True, cls=BackupFormatEncoder)
                    if cipher is not None:
                        fichier.write(cipher.update(lzma_compressor.compress(tran_json.encode('utf-8'))))
                    else:
                        fichier.write(lzma_compressor.compress(tran_json.encode('utf-8')))

                    # Une transaction par ligne
                    if cipher is not None:
                        fichier.write(cipher.update(lzma_compressor.compress(b'\n')))
                    else:
                        fichier.write(lzma_compressor.compress(b'\n'))

                    # La transaction est bonne, on l'ajoute a la liste inclue dans le backup
                    liste_uuid_transactions.append(uuid_transaction)
                except HachageInvalide:
                    self.__logger.error("Transaction hachage invalide %s: transaction exclue du backup de %s" % (uuid_transaction, nom_collection_mongo))
                    # Marquer la transaction comme invalide pour backup
                    liste_uuids_invalides.append(uuid_transaction)
                except (CertificatInvalide, CertificatInconnu):
                    self.__logger.error("Erreur, certificat de transaction invalide : %s" % uuid_transaction)
                    liste_uuids_invalides.append(uuid_transaction)

            if cipher is not None:
                fichier.write(cipher.update(lzma_compressor.flush()))
                fichier.write(cipher.finalize())
            else:
                fichier.write(lzma_compressor.flush())

        if len(liste_uuid_transactions) > 0:
            # Calculer SHA512 du fichier de backup des transactions
            hachage_catalogue = self.sauvegarder_catalogue(backup_nomfichier, backup_workdir, catalogue_backup,
                                                           catalogue_nomfichier, cles_set, info_backup,
                                                           path_fichier_backup)

            info_backup[ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE] = hachage_catalogue

        else:
            self.__logger.info("Backup: aucune transaction, backup annule")
            info_backup = {
                'liste_uuids_invalides': liste_uuids_invalides
            }

        return info_backup

    def sauvegarder_catalogue(self, backup_nomfichier, backup_workdir, catalogue_backup, catalogue_nomfichier,
                              cles_set, info_backup, path_fichier_backup):
        sha512 = hashlib.sha512()
        with open(path_fichier_backup, 'rb') as fichier:
            sha512.update(fichier.read())
        sha512_digest = 'sha512_b64:' + b64encode(sha512.digest()).decode('utf-8')
        catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE] = sha512_digest
        catalogue_backup[ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER] = backup_nomfichier
        # Changer les set() par des list() pour extraire en JSON
        for cle in cles_set:
            if isinstance(catalogue_backup[cle], set):
                catalogue_backup[cle] = list(catalogue_backup[cle])
        # Generer l'entete et la signature pour le catalogue
        catalogue_json = json.dumps(catalogue_backup, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
        # Recharger le catalogue pour avoir le format exact (e.g. encoding dates)
        catalogue_backup = json.loads(catalogue_json)
        catalogue_backup = self._contexte.generateur_transactions.preparer_enveloppe(
            catalogue_backup, ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE, ajouter_certificats=True)
        catalogue_json = json.dumps(catalogue_backup, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
        info_backup['catalogue'] = catalogue_backup
        # Sauvegarder catlogue sur disque pour transferer
        path_catalogue = path.join(backup_workdir, catalogue_nomfichier)
        info_backup['path_catalogue'] = path_catalogue
        with lzma.open(path_catalogue, 'wt') as fichier:
            # Dump du catalogue en format de transaction avec DateFormatEncoder
            fichier.write(catalogue_json)
        sha512 = hashlib.sha512()
        with open(path_catalogue, 'rb') as fichier:
            sha512.update(fichier.read())
        sha512_digest = 'sha512_b64:' + b64encode(sha512.digest()).decode('utf-8')

        return sha512_digest

    def preparer_catalogue(self, backup_nomfichier, catalogue_nomfichier, chainage_backup_precedent, heure,
                           sous_domaine):
        catalogue_backup = {
            ConstantesBackup.LIBELLE_DOMAINE: sous_domaine,
            ConstantesBackup.LIBELLE_SECURITE: self.__niveau_securite,
            ConstantesBackup.LIBELLE_HEURE: heure,

            ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER: catalogue_nomfichier,
            ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER: backup_nomfichier,
            ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE: None,

            # Conserver la liste des certificats racine, intermediaire et noeud necessaires pour
            # verifier toutes les transactions de ce backup
            ConstantesBackup.LIBELLE_CERTS_RACINE: set(),
            ConstantesBackup.LIBELLE_CERTS_INTERMEDIAIRES: set(),
            ConstantesBackup.LIBELLE_CERTS: set(),
            ConstantesBackup.LIBELLE_CERTS_CHAINE_CATALOGUE: list(),

            # Conserver la liste des grosfichiers requis pour ce backup
            ConstantesBackup.LIBELLE_FUUID_GROSFICHIERS: dict(),

            ConstantesBackup.LIBELLE_BACKUP_PRECEDENT: chainage_backup_precedent,
        }
        # Ajouter le certificat du module courant pour etre sur
        enveloppe_certificat_module_courant = self._contexte.signateur_transactions.enveloppe_certificat_courant
        # Conserver la chaine de validation du catalogue
        certificats_validation_catalogue = [
            enveloppe_certificat_module_courant.fingerprint_ascii
        ]
        catalogue_backup[ConstantesBackup.LIBELLE_CERTS_CHAINE_CATALOGUE] = certificats_validation_catalogue
        certs_pem = {
            enveloppe_certificat_module_courant.fingerprint_ascii: enveloppe_certificat_module_courant.certificat_pem
        }
        catalogue_backup[ConstantesBackup.LIBELLE_CERTS_PEM] = certs_pem
        liste_enveloppes_cas = self._contexte.verificateur_certificats.aligner_chaine_cas(
            enveloppe_certificat_module_courant)
        for cert_ca in liste_enveloppes_cas:
            fingerprint_ca = cert_ca.fingerprint_ascii
            certificats_validation_catalogue.append(fingerprint_ca)
            certs_pem[fingerprint_ca] = cert_ca.certificat_pem
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

    def _traiter_transaction(self, transaction, heure: datetime.datetime):
        """
        Verifie la signature de la transaction et extrait les certificats requis pour le backup.

        :param transaction:
        :return:
        """
        try:
            enveloppe_initial = self._contexte.verificateur_transaction.verifier(transaction)
        except AutorisationConditionnelleDomaine as acd:
            # OK, c'est un backup d'une transaction deja sauvegardee. Le domaine va re-valider la permission
            # sur restauration / regeneration
            enveloppe_initial = acd.enveloppe

        enveloppe = enveloppe_initial

        liste_enveloppes_cas = self._contexte.verificateur_certificats.aligner_chaine_cas(enveloppe_initial)

        # S'assurer que le certificat racine correspond a la transaction
        ca_racine = liste_enveloppes_cas[-1]
        if ca_racine.fingerprint_base58 != transaction['en-tete']['idmg']:
            raise ValueError("Transaction IDMG ne correspond pas au certificat racine " + enveloppe.fingerprint_base58)

        # Extraire liste de fingerprints
        liste_cas = [enveloppe.fingerprint_ascii for enveloppe in liste_enveloppes_cas]

        return {
            'certificats': [enveloppe_initial.fingerprint_ascii],
            'certificats_intermediaires': liste_cas[:-1],
            'certificats_racine': [liste_cas[-1]],
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
        self._contexte.generateur_transactions.emettre_message(evenement, domaine_action, exchanges=[Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE])

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
        self._contexte.message_dao.transmettre_message(evenement, Constantes.TRANSACTION_ROUTING_EVENEMENT)

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
            self._contexte.verificateur_transaction.verifier(catalogue)

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

    def creer_backup_quoditien(self, domaine: str, jour: datetime.datetime):
        coldocs = self._contexte.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)

        # Calculer la fin du jour comme etant le lendemain, on fait un "<" dans la selection
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

        annee_fin = annee.year
        fin_annee = datetime.datetime(year=annee_fin, month=1, day=1)

        # Faire la liste des catalogues de backups qui sont dus
        filtre_backups_annuels_dirty = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_ANNUEL,
            ConstantesBackup.LIBELLE_DOMAINE: {'$regex': '^' + domaine},
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            ConstantesBackup.LIBELLE_ANNEE: {'$lte': fin_annee}
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
            evenement_contenu, domaine, exchanges=[Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS]
        )

    def transmettre_trigger_jour_precedent(self, heure_plusvieille):
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
        hachage_backup = self._contexte.verificateur_transaction.hacher_contenu(entete, hachage=hashes.SHA512())
        hachage_backup = 'sha512_b64:' + hachage_backup
        return hachage_backup


# class HandlerBackupApplication:
#
#     def __init__(self, contexte):
#         # self.__handler_requetes = handler_requetes
#         self.__contexte = contexte
#         self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
#
#         self.__backup_util = BackupUtil(self.__contexte)
#         self.__generateur_transactions = self.__contexte.generateur_transactions
#         self.__configuration = self.__contexte.configuration
#
#     def upload_backup(self, catalogue_backup: dict, transaction_maitredescles: dict, path_archive: str):
#         """
#
#         :param nom_application: Nom du service, utilise pour le nom du catalogue et upload path
#         :param path_archives: Repertoire avec toutes les archives a inclure dans le backup
#         :return:
#         """
#         nom_application = catalogue_backup['application']
#
#         fichiers_temporaire = [path_archive]
#         try:
#             # nom_fichier_backup, digest_archive, transaction_maitredescles = self._chiffrer_archive(
#             #     nom_application, path_archive, catalogue_backup)
#             # fichiers_temporaire.append(nom_fichier_backup)  # Permet de supprimer le fichier a la fin
#             # self.__logger.debug("Compression et chiffrage complete : %s\nDigest : %s" % (nom_fichier_backup, digest_archive))
#             # catalogue_backup[ConstantesBackup.LIBELLE_ARCHIVE_HACHAGE] = digest_archive
#
#             transactions = self._preparer_transactions_backup(catalogue_backup, transaction_maitredescles)
#             self._put_backup(nom_application, transactions, path_archive)
#
#         finally:
#             # Supprimer les archives
#             for fichier in fichiers_temporaire:
#                 try:
#                     os.remove(fichier)
#                 except FileNotFoundError as e:
#                     self.__logger.warning("Erreur nettoyage fichier " + str(e))
#
#     def _put_backup(self, nom_application, transactions: dict, nom_fichier_backup: str):
#         self.transmettre_evenement_backup(
#             ConstantesBackup.EVENEMENT_BACKUP_APPLICATION_CATALOGUE_PRET, nom_application)
#
#         # Transferer vers consignation_fichier
#         catalogue = transactions['catalogue']
#         data = {
#             'catalogue': json.dumps(catalogue)
#         }
#         transaction_maitredescles = transactions.get('maitredescles')
#         if transaction_maitredescles is not None:
#             data['transaction_maitredescles'] = json.dumps(transaction_maitredescles)
#
#         # Preparer URL de connexion a consignationfichiers
#         url_consignationfichiers = 'https://%s:%s' % (
#             self.__configuration.serveur_consignationfichiers_host,
#             self.__configuration.serveur_consignationfichiers_port
#         )
#
#         with open(nom_fichier_backup, 'rb') as fichier_archive:
#             files = {
#                 'application': (nom_fichier_backup, fichier_archive, 'application/octet-stream'),
#             }
#
#             certfile = self.__configuration.mq_certfile
#             keyfile = self.__configuration.mq_keyfile
#
#             r = requests.put(
#                 '%s/backup/application/%s' % (url_consignationfichiers, nom_application),
#                 data=data,
#                 files=files,
#                 verify=self.__configuration.mq_cafile,
#                 cert=(certfile, keyfile)
#             )
#
#         if r.status_code == 200:
#             self.transmettre_evenement_backup(
#                 ConstantesBackup.EVENEMENT_BACKUP_APPLICATION_UPLOAD_CONFIRME, nom_application)
#
#         self.transmettre_evenement_backup(
#             ConstantesBackup.EVENEMENT_BACKUP_APPLICATION_TERMINE, nom_application)
#
#     def _preparer_transactions_backup(self, catalogue_backup: dict, transaction_maitredescles: dict):
#         """
#         Complete le contenu des transactions catalogue, maitre des cles. Les conserve dans des fichiers temporaires.
#         :param catalogue_backup:
#         :param transaction_maitredescles:
#         :return:
#         """
#
#         #     "application": "Application___",
#         #     "securite": "3.protege",
#         #     "catalogue_nomfichier": "application_app_catalogue_202010070000.json.xz",
#         #     "archive_nomfichier": "application_app_archive_2020100700.tar.xz.mgs1",
#         #     "archive_hachage": "sha512_b64:NZXajIM8OnHR505RynFyL7olyXxnw5ChqY8+Z391GzIRLsQEEiuGtK1iJ+4YIdlTUE/VxsPvOPZLt46PM7Cmew==",
#
#         # Signer les transactions
#         catalogue_backup = self.__generateur_transactions.preparer_enveloppe(
#             catalogue_backup,
#             ConstantesBackup.TRANSACTION_CATALOGUE_APPLICATION,
#             ajouter_certificats=True
#         )
#         transaction_maitredescles = self.__generateur_transactions.preparer_enveloppe(
#             transaction_maitredescles,
#             'MaitreDesCles.' + Constantes.ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPAPPLICATION,
#             ajouter_certificats=True)
#
#         # fd_catalogue, tmpfile_catalogue = tempfile.mkstemp(dir=path_fichiers, prefix='transaction_', suffix='.json')
#         # fp_catalogue = os.fdopen(fd_catalogue, 'w')
#         # json.dump(catalogue_backup, fp_catalogue)
#         # fp_catalogue.close()
#
#         # fd_maitredescles, tmpfile_maitredescles = tempfile.mkstemp(dir=path_fichiers, prefix='transaction_', suffix='.json')
#         # fp_maitredescles = os.fdopen(fd_maitredescles, 'w')
#         # json.dump(transaction_maitredescles, fp_maitredescles)
#         # fp_maitredescles.close()
#
#         # return [tmpfile_catalogue, tmpfile_maitredescles]
#         return {'maitredescles': transaction_maitredescles, 'catalogue': catalogue_backup}
#
#     def _chiffrer_archive(self, nom_application, path_archive, catalogue_backup: dict):
#         date_formattee = datetime.datetime.utcnow().strftime('%Y%m%d%H%M')
#         nom_fichier_backup = 'application_%s_archive_%s.tar.xz.mgs1' % (nom_application, date_formattee)
#         nom_fichier_catalogue = 'application_%s_catalogue_%s.json' % (nom_application, date_formattee)
#         catalogue_backup[ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER] = nom_fichier_backup
#         catalogue_backup[ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER] = nom_fichier_catalogue
#
#         # Faire requete pour obtenir les cles de chiffrage
#         domaine_action = 'MaitreDesCles.' + Constantes.ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
#         cles_chiffrage = self.__handler_requetes.requete(domaine_action)
#         self.__logger.debug("Cles chiffrage recu : %s" % cles_chiffrage)
#
#         cipher, transaction_maitredescles = self.__backup_util.preparer_cipher(
#             catalogue_backup, cles_chiffrage, nom_application=nom_application)
#
#         basedir = path.dirname(path_archive)
#         self.__logger.debug("Compression et chiffrage de %s ver %s" % (path_archive, nom_fichier_backup))
#
#         # Compresser et chiffrer l'archive
#         block_size = 64 * 1024
#         with open(path_archive, 'rb') as input:
#             with open(nom_fichier_backup, 'wb') as output:
#                 lzma_compressor = lzma.LZMACompressor()
#                 output.write(cipher.start_encrypt())
#
#                 data = input.read(block_size)
#                 while len(data) > 0:
#                     data = lzma_compressor.compress(data)
#                     data = cipher.update(data)
#                     output.write(data)
#                     data = input.read(block_size)
#
#                 output.write(cipher.update(lzma_compressor.flush()))
#                 output.write(cipher.finalize())
#         digest_archive = cipher.digest
#
#         return nom_fichier_backup, digest_archive, transaction_maitredescles
#
#     def transmettre_evenement_backup(self, evenement: str, application: str, info: dict = None):
#         evenement_contenu = {
#             Constantes.EVENEMENT_MESSAGE_EVENEMENT: evenement,
#             ConstantesBackup.LIBELLE_APPLICATION: application,
#         }
#         if info:
#             evenement_contenu['info'] = info
#
#         domaine = 'evenement.Backup.%s' % evenement
#
#         self.__generateur_transactions.emettre_message(
#             evenement_contenu, domaine, exchanges=[Constantes.SECURITE_PROTEGE]
#         )


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

    def __init__(self, contexte: ContexteRessourcesMilleGrilles, stream, path_output: str = None):
        self.__contexte = contexte
        self.__path_output = path_output
        self.__catalogue_horaire_courant = None
        self.__channel = None
        self.__nom_queue: Optional[str] = None
        self.__thread: Optional[Thread] = None

        self.__handler_messages = ReceptionMessage(self, contexte.message_dao, contexte.configuration)

        # wrapper = WrapperDownload(resultat.iter_content(chunk_size=512 * 1024))
        wrapper = WrapperDownload(stream)
        self.__tar_stream = tarfile.open(fileobj=wrapper, mode='r|', debug=3, errorlevel=3)

        self.__event_execution = Event()
        self.__event_attente_reponse = Event()
        self.__reponse_cle: Optional[dict] = None

        self.__cle_iv_transactions: Optional[dict] = None

        self.__chaine_pem_courante = contexte.signateur_transactions.chaine_certs

        # Statistiques de restauration, erreurs, etc
        self.__rapport_restauration = RapportRestauration()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def start(self) -> Event:
        """
        Demarre execution
        :return: Event qui est set() a la fin de l'execution
        """
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
        self.__logger.info("MQ Channel ferme")

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
        if type_archive == 'annuelle':
            self._process_archive_aggregee(nom_fichier, file_object)
        elif type_archive == 'quotidienne':
            self._process_archive_aggregee(nom_fichier, file_object)
        elif type_archive == 'snapshot_catalogue':
            self._process_archive_snapshot_catalogue(nom_fichier, file_object)
        elif type_archive == 'snapshot_transactions':
            self._process_archive_snapshot_transaction(nom_fichier, file_object)
        elif type_archive == 'catalogue':
            pass  # Catalogue annuel ou quotidien
        elif type_archive == 'horaire_catalogue':
            self._process_archive_horaire_catalogue(nom_fichier, file_object)
        elif type_archive == 'horaire_transactions':
            self._process_archive_horaire_transaction(nom_fichier, file_object)
        elif type_archive == 'grosfichier':
            pass  # Skip les fichiers
        else:
            raise TypeArchiveInconnue(type_archive)

    def _process_archive_aggregee(self, nom_fichier: str, file_object):
        self.__logger.debug("Traitement archive annuelle/quotidienne")
        try:
            tar_quotidienne = tarfile.open(fileobj=file_object, mode='r|')
            self.__logger.debug("Liste contenu archive annuelle/quotidienne")

            for tarinfo_quotidien in tar_quotidienne:
                path_fichier = tarinfo_quotidien.name
                fo = tar_quotidienne.extractfile(tarinfo_quotidien)
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
        self.__catalogue_horaire_courant = catalogue_json

    def _process_archive_horaire_transaction(self, nom_fichier: str, file_object):
        self.__logger.debug("Transactions horaire")
        self._extract_transaction(nom_fichier, file_object)

    def _process_archive_snapshot_catalogue(self, nom_fichier: str, file_object):
        # self.__logger.debug("Catalogue snapshot")
        catalogue_json = self._extract_catalogue(nom_fichier, file_object)
        self.__logger.debug("Catalogue snapshot : %s" % catalogue_json)
        self.__catalogue_horaire_courant = catalogue_json

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
        catalogue = self.__catalogue_horaire_courant
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
                    digest_transactions_catalogue = catalogue['transactions_hachage']
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

        nom_fichier_parts = nom_fichier.split('_')
        if len(nom_fichier_parts) == 3:
            date_fichier = nom_fichier_parts[1]
            if len(date_fichier) == 8:
                type_archive = 'quotidienne'
            elif len(date_fichier) == 4:
                type_archive = 'annuelle'
            else:
                raise TypeArchiveInconnue("Type archive inconnue : %s" % nom_fichier)
        elif len(nom_fichier_parts) == 4:
            date_fichier = nom_fichier_parts[2]
            try:
                if len(date_fichier) == 10:
                    type_archive = 'horaire_' + nom_fichier_parts[1]
                elif len(date_fichier) < 10:
                    type_archive = 'catalogue'
                else:
                    try:
                        date_fichier.index('SNAPSHOT')
                        type_archive = 'snapshot_' + nom_fichier_parts[1]
                    except ValueError:
                        raise TypeArchiveInconnue("Type archive inconnue : %s" % nom_fichier)
            except ValueError:
                raise TypeArchiveInconnue("Type archive inconnue : %s" % nom_fichier)
        else:
            raise TypeArchiveInconnue("Type archive inconnue : %s" % nom_fichier)

        self.__logger.debug("Archive %s : %s" % (type_archive, nom_fichier))
        return type_archive

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
    pass

import datetime
import json
import lzma
import logging
from threading import Event
from pymongo.errors import DuplicateKeyError

from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes, ConstantesGrosFichiers, ConstantesBackup
from millegrilles.util.JSONMessageEncoders import BackupFormatEncoder, decoder_backup

from millegrilles.Domaines import HandlerBackupDomaine
from millegrilles.domaines.GrosFichiers import HandlerBackupGrosFichiers

logging.basicConfig()
logging.getLogger('millegrilles.Domaines.HandlerBackupDomaine').setLevel(logging.DEBUG)
logging.getLogger('millegrilles.Domaines.HandlerBackupGrosFichiers').setLevel(logging.DEBUG)

contexte = ContexteRessourcesDocumentsMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger.setLevel(logging.DEBUG)

        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.handler_backup_senseurspassifs = HandlerBackupDomaine(
            self.contexte,
            SenseursPassifsConstantes.DOMAINE_NOM,
            SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM,
            SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
        self.handler_grosfichiers = HandlerBackupGrosFichiers(self.contexte)

        self.channel = None
        self.event_recu = Event()

        # Preparer URL de connexion a consignationfichiers
        self.url_consignationfichiers = 'https://%s:%s' % (
            self._contexte.configuration.serveur_consignationfichiers_host,
            self._contexte.configuration.serveur_consignationfichiers_port,
        )

        self.idmg = 'CRnbtUbwzUuTg2h88ALe4Phg441Emgp8FibqkJ'

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        self.__logger.debug('Reponse recue : %s' % str(body))
        self.event_recu.set()  # Termine

    def executer(self):
        try:
            # self.backup_domaine_senseurpassifs()
            # self.backup_domaine_grosfichiers()

            # self.prerarerStagingRestauration()

            # self.restore_domaine(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
            # self.restore_domaine(ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM)

            # Backup quotidien
            # self.trigger_backup_horaire(ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM)
            # self.trigger_backup_horaire(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
            # self.creer_backup_quoditien(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)

            # Declenchement global
            self.trigger_backup_global()

            # self.reset_evenements()
        finally:
            pass
            # self.event_recu.set()  # Termine

    def trigger_backup_horaire(self, domaine):
        timestamp_courant = datetime.datetime.utcnow()

        commande_backup_quotidien = {
            ConstantesBackup.LIBELLE_HEURE: int(timestamp_courant.timestamp()),
            ConstantesBackup.LIBELLE_DOMAINE: domaine,
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_quotidien,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace(
                '_DOMAINE_', domaine),
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_horaire'
        )

    def trigger_backup_global(self):
        timestamp_courant = datetime.datetime.utcnow()

        commande_backup_quotidien = {
            ConstantesBackup.LIBELLE_HEURE: int(timestamp_courant.timestamp()),
            ConstantesBackup.LIBELLE_SECURITE: Constantes.SECURITE_PRIVE,
        }
        self._contexte.generateur_transactions.transmettre_commande(
            commande_backup_quotidien,
            ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE_GLOBAL,
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            reply_to=self.queue_name,
            correlation_id='trigger_backup_horaire'
        )

    def backup_transactions_senseurspassifs_testinit(self):
        coltrans = self.contexte.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        filtre = {}
        curseur = coltrans.find(filtre)

        with lzma.open('/tmp/senseurspassifs.json.xz', 'wt') as fichier:
            for transaction in curseur:
                json.dump(transaction, fichier, sort_keys=True, ensure_ascii=True, cls=BackupFormatEncoder)
                # Une transaction par ligne
                fichier.write('\n')
                # json_transaction = self.__json_helper.dict_vers_json(transaction)
                # self.__logger.debug("Transaction %s" % json_transaction)

    def backup_domaine_senseurpassifs(self):
        nom_collection_mongo = SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM
        heure_courante = datetime.datetime.utcnow()
        # heure = datetime.datetime(year=2020, month=3, day=6, hour=21, tzinfo=datetime.timezone.utc)
        heure = datetime.datetime(year=heure_courante.year, month=heure_courante.month, day=heure_courante.day, hour=heure_courante.hour, tzinfo=datetime.timezone.utc)
        heure = heure - datetime.timedelta(hours=1)
        self.__logger.debug("Faire backup horaire de %s" % str(heure))
        self.handler_backup_senseurspassifs.backup_domaine(heure, nom_collection_mongo)

    def backup_domaine_grosfichiers(self):
        nom_collection_mongo = ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM
        heure_courante = datetime.datetime.utcnow()
        # heure = datetime.datetime(year=2020, month=3, day=15, hour=22, tzinfo=datetime.timezone.utc)
        heure = datetime.datetime(year=heure_courante.year, month=heure_courante.month, day=heure_courante.day, hour=heure_courante.hour, tzinfo=datetime.timezone.utc)
        heure = heure - datetime.timedelta(hours=1)
        self.__logger.debug("Faire backup horaire de %s" % str(heure))
        self.handler_grosfichiers.backup_domaine(heure, nom_collection_mongo)

    def restore_domaine(self, nom_collection_mongo):

        path_folder = '/tmp/mgbackup'

        self.handler_grosfichiers.restaurer_domaines_horaires(nom_collection_mongo)

    def restore_horaire_domaine(self, nom_collection_mongo: str, idmg: str, path_fichier: str):
        coltrans = self.contexte.document_dao.get_collection(nom_collection_mongo)

        with lzma.open(path_fichier, 'rt') as fichier:
            for line in fichier:
                transaction = json.loads(line, object_hook=decoder_backup)

                self.__logger.debug("Transaction : %s" % str(transaction))
                try:
                    coltrans.insert(transaction)
                except DuplicateKeyError:
                    self.__logger.warning("Transaction existe deja : %s" % transaction['en-tete']['uuid-transaction'])

    def reset_evenements(self):
        collections = [
            ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM,
            SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM,
            'millegrilles.domaines.Annuaire',
            'millegrilles.domaines.MaitreDesCles',
            'millegrilles.domaines.Parametres',
            'millegrilles.domaines.Pki',
            'millegrilles.domaines.Plume',
            'millegrilles.domaines.Principale',
            'millegrilles.domaines.Taches',
        ]

        for coll in collections:
            collection_domaine = self.contexte.document_dao.get_collection(coll)

            evenement_libelle_backup = '_evenements.%s.backup_horaire' % self.idmg
            evenement_libelle_restauree = '_evenements.%s.transaction_restauree' % self.idmg
            ops = {'$unset': {evenement_libelle_backup: True, evenement_libelle_restauree: True}}

            collection_domaine.update_many({}, ops)

        col_backup = self.contexte.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        col_backup.update_many(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN},
            {'$set': {'dirty_flag': True}}
        )

    # def creer_backup_quoditien(self, nom_collection_mongo: str):
    #     self.handler_backup.creer_backup_quoditien(nom_collection_mongo)
    #
    #     coldocs = self.contexte.document_dao.get_collection(nom_collection_mongo)
    #     collection_pki = self.contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
    #
    #     # Faire la liste des catalogues de backups qui sont dus
    #     filtre_backups_quotidiens_dirty = {
    #         Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
    #         ConstantesBackup.LIBELLE_DIRTY_FLAG: True
    #     }
    #     curseur_catalogues = coldocs.find(filtre_backups_quotidiens_dirty)
    #
    #     for catalogue in curseur_catalogues:
    #
    #         # S'assurer que le catalogue contient tous les certificats
    #         certs = catalogue[ConstantesBackup.LIBELLE_CERTS_RACINE].copy()
    #         certs.extend(catalogue[ConstantesBackup.LIBELLE_CERTS_INTERMEDIAIRES])
    #         certs.extend(catalogue[ConstantesBackup.LIBELLE_CERTS])
    #
    #         try:
    #             certs_pem = catalogue[ConstantesBackup.LIBELLE_CERTS_PEM]
    #         except KeyError:
    #             certs_pem = dict()
    #             catalogue[ConstantesBackup.LIBELLE_CERTS_PEM] = certs_pem
    #
    #         # Ajouter le certificat du module courant pour etre sur
    #         enveloppe_certificat_module_courant = self.contexte.signateur_transactions.enveloppe_certificat_courant
    #
    #         certs_pem[enveloppe_certificat_module_courant.fingerprint_ascii] = enveloppe_certificat_module_courant.certificat_pem
    #
    #         liste_enveloppes_cas = self._contexte.verificateur_certificats.aligner_chaine_cas(enveloppe_certificat_module_courant)
    #         for cert_ca in liste_enveloppes_cas:
    #             fingerprint_ca = cert_ca.fingerprint_ascii
    #             certs_pem[fingerprint_ca] = cert_ca.certificat_pem
    #
    #         certs_manquants = set()
    #         for fingerprint in certs:
    #             if not certs_pem.get(fingerprint):
    #                 certs_manquants.add(fingerprint)
    #
    #         self.__logger.debug("Liste de certificats a trouver: %s" % str(certs_manquants))
    #
    #         if len(certs_manquants) > 0:
    #             filtre_certs_pki = {
    #                 ConstantesPki.LIBELLE_FINGERPRINT: {'$in': list(certs_manquants)},
    #                 ConstantesPki.LIBELLE_CHAINE_COMPLETE: True,
    #                 Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
    #                     ConstantesPki.LIBVAL_CERTIFICAT_ROOT,
    #                     ConstantesPki.LIBVAL_CERTIFICAT_INTERMEDIAIRE,
    #                     ConstantesPki.LIBVAL_CERTIFICAT_MILLEGRILLE,
    #                     ConstantesPki.LIBVAL_CERTIFICAT_NOEUD,
    #                 ]}
    #             }
    #             curseur_certificats = collection_pki.find(filtre_certs_pki)
    #             for cert in curseur_certificats:
    #                 fingerprint = cert[ConstantesPki.LIBELLE_FINGERPRINT]
    #                 pem = cert[ConstantesPki.LIBELLE_CERTIFICAT_PEM]
    #                 certs_pem[fingerprint] = pem
    #                 certs_manquants.remove(fingerprint)
    #
    #             # Verifier s'il manque des certificats
    #             if len(certs_manquants) > 0:
    #                 raise Exception("Certificats manquants : %s" % str(certs_manquants))
    #
    #         # Filtrer catalogue pour retirer les champs Mongo
    #         for champ in catalogue.copy().keys():
    #             if champ.startswith('_') or champ in [ConstantesBackup.LIBELLE_DIRTY_FLAG]:
    #                 del catalogue[champ]
    #
    #         # Generer l'entete et la signature pour le catalogue
    #         catalogue_json = json.dumps(catalogue, sort_keys=True, ensure_ascii=True, cls=DateFormatEncoder)
    #         catalogue = json.loads(catalogue_json)
    #         catalogue_quotidien = self._contexte.generateur_transactions.preparer_enveloppe(
    #             catalogue, ConstantesBackup.TRANSACTION_CATALOGUE_QUOTIDIEN)
    #         self.__logger.debug("Catalogue:\n%s" % catalogue_quotidien)
    #
    #         # Transmettre le catalogue au consignateur de fichiers sous forme de commande. Ceci declenche la
    #         # creation de l'archive de backup. Une fois termine, le consignateur de fichier va transmettre une
    #         # transaction de catalogue quotidien.
    #         self._contexte.generateur_transactions.transmettre_commande(
    #             {'catalogue': catalogue_quotidien}, ConstantesBackup.COMMANDE_BACKUP_QUOTIDIEN)

    def prerarerStagingRestauration(self):
        self._contexte.generateur_transactions.transmettre_commande(
            {},
            ConstantesBackup.COMMANDE_BACKUP_PREPARER_RESTAURATION,
            reply_to=self.queue_name,
            correlation_id='backup_transactions'
        )

# -------
sample = MessagesSample()

# TEST
# sample.executer()

# FIN TEST
sample.event_recu.wait(200)
sample.deconnecter()

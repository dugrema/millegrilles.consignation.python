import datetime
import pytz
import json
import os
import lzma
import tarfile
import tempfile

from base64 import b64decode, b64encode
from io import BytesIO, StringIO
from lzma import LZMAFile, LZMAError
from typing import Optional

from unit.helpers.TestBaseContexte import TestCaseContexte
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup, ConstantesGrosFichiers
from millegrilles.util.BackupModule import BackupUtil, HandlerBackupDomaine, InformationSousDomaineHoraire, \
    ArchivesBackupParser, TypeArchiveInconnue
from millegrilles.transaction.FormatteurMessage import FormatteurMessageMilleGrilles
from millegrilles.domaines.GrosFichiers import HandlerBackupGrosFichiers
from millegrilles.domaines.MaitreDesCles import HandlerBackupMaitreDesCles


UT_TEMP_FOLDER = '/tmp/ut_backupmoduletest'
try:
    os.mkdir(UT_TEMP_FOLDER)
except FileExistsError:
    pass


class RequestsReponse:

    def __init__(self):
        self.status_code = 200
        self.json = {
            'ok': True,
        }
        self.headers = list()

    @property
    def text(self):
        return json.dumps(self.json)


class BackupUtilTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()
        self.backup_util = BackupUtil(self.contexte)

    def test_preparer_cipher(self):
        clecert = self.contexte.configuration.cle
        info_cles = {
            'certificat': [clecert.cert_bytes.decode('utf-8')],
            'certificat_millegrille': clecert.chaine[-1],
            'certificats_backup': dict(),
        }
        heure_str = '2020010100'
        cipher, transaction_maitrecles = self.backup_util.preparer_cipher(dict(), info_cles, heure_str)

        self.assertIsNotNone(cipher, "Cipher n'a pas ete genere")
        self.assertIsNotNone(cipher.iv, "IV pas inclus dans cipher")
        self.assertIsNotNone(cipher.password, "password pas inclus dans cipher")

        # Verifier presence du IV, cles
        self.assertIsNotNone(transaction_maitrecles.get('iv'), "IV absent de la transaction maitrecles")
        self.assertIsNotNone(transaction_maitrecles.get('cles'), "Cles chiffrees absentes de la transaction maitrecles")

        resultat = cipher.start_encrypt()
        resultat = resultat + cipher.update(b'test')
        resultat = resultat + cipher.finalize()
        self.assertIsNotNone(resultat, "Cipher n'est pas fonctionnel")
        self.assertEqual(4, len(resultat), "Erreur taille resultat cipher")

        self.assertIsNotNone(cipher.tag, "Le compute tag n'est pas present")

        self.__class__.logger.debug("Transaction maitrecles : %s" % transaction_maitrecles)

    def test_chiffrer_cle(self):
        clecert = self.contexte.configuration.cle
        certs_cles_backup = [
            clecert.cert_bytes.decode('utf-8'),
            clecert.chaine[-1]
        ]
        password = b'abcdefghijkl12345678910111213141'
        cles_chiffrees = self.backup_util.chiffrer_cle(certs_cles_backup, password)

        self.assertEqual(2, len(cles_chiffrees))

        # S'assurer que les cles sont formattes en base64 valide
        for cle in cles_chiffrees.values():
            resultat = b64decode(cle)


class HandlerBackupDomaineTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()

        self.handler_protege = HandlerBackupDomaine(
            self.contexte, "TestDomaine", "TestTransactions", "TestDocuments",
            niveau_securite=Constantes.SECURITE_PROTEGE
        )
        self.handler_public = HandlerBackupDomaine(
            self.contexte, "TestDomaine", "TestTransactions", "TestDocuments",
            niveau_securite=Constantes.SECURITE_PUBLIC
        )

        # Override methode requests
        self.handler_protege._requests_put = self.__requests_put
        self.handler_public._requests_put = self.__requests_put

        self.backup_util = BackupUtil(self.contexte)

        self.enveloppe_certificat = self.contexte.validateur_pki.valider(self.contexte.configuration.cle.chaine)
        idmg = self.enveloppe_certificat.subject_organization_name
        self.formatteur = FormatteurMessageMilleGrilles(idmg, self.contexte.signateur_transactions)

        self.contexte.generateur_transactions.reset()

        self._requests_calls = list()
        self._requests_response = RequestsReponse()

    def __requests_put(self, *args, **kwargs):
        self.logger.info("CALL requests_put:\n%s\n%s" % (args, kwargs))
        self._requests_calls.append({
            'args': args,
            'kwargs': kwargs,
        })
        return self._requests_response

    def test_transmettre_evenement_backup(self):
        ts = datetime.datetime.utcnow()
        self.handler_protege.transmettre_evenement_backup('test_transmettre_evenement_backup', 'evenement_test', ts)

        # Stub generateur transaction, verifier message transmis
        generateur_transactions = self.contexte.generateur_transactions
        liste_messages = generateur_transactions.liste_emettre_message

        # S'assurer que l'evenement a ete emis
        self.assertEqual(1, len(liste_messages))

    def test_effectuer_requete_domaine(self):
        contexte = self.contexte
        document_dao = contexte.document_dao

        # Prep data
        ts = datetime.datetime.utcnow()
        contexte.document_dao.valeurs_aggregate.append('dummy')

        # Call methode a tester
        resultat_aggregate = self.handler_protege._effectuer_requete_domaine(ts)

        # Verification
        self.assertEqual('dummy', resultat_aggregate)
        call_aggregate = document_dao.calls_aggregate[0]
        requete_match = call_aggregate['args'][0][0]['$match']
        self.assertEqual(ts, requete_match['_evenements.transaction_traitee']['$lt'])

    def test_preparer_curseur_transactions(self):
        contexte = self.contexte
        document_dao = contexte.document_dao

        # Prep data
        ts = datetime.datetime.utcnow()
        contexte.document_dao.valeurs_find.append('dummy')

        # Call methode a tester
        curseur = self.handler_protege.preparer_curseur_transactions('collection_test', 'sousdomaine_test', heure_max=ts)
        self.assertEqual('dummy', curseur)

        # Verification
        call_find = document_dao.calls_find[0]
        params_find = call_find['args'][0]
        self.assertEqual(params_find['en-tete.domaine']['$regex'], '^sousdomaine_test\\.[A-Za-z0-9_\\/\\-]+$')
        self.assertEqual(params_find['_evenements.transaction_traitee']['$lt'], ts)

    def test_preparer_sousgroupes_horaires(self):
        contexte = self.contexte
        document_dao = contexte.document_dao

        # Prep data
        ts = datetime.datetime.utcnow()
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        document_dao.valeurs_aggregate.append([
            {'_id': {'timestamp': ts_groupe}, 'sousdomaine': [['sousdomaine_test', 'abcd', '1234']], 'count': 7}
        ])

        # Call methode a tester
        resultat = self.handler_protege.preparer_sousgroupes_horaires(ts)

        # Verification
        self.assertEqual(1, len(resultat))
        for domaine, groupe in resultat.items():
            groupe = groupe.liste_horaire[0]
            self.assertEqual(pytz.UTC.localize(ts_groupe), groupe.heure)
            self.assertEqual('sousdomaine_test.abcd.1234', groupe.sous_domaine)

    def test_preparation_backup_horaire_public(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)

        self.handler_public._preparation_backup_horaire(information_sousgroupe)

        # Verification
        self.assertEqual('sousdomaine_test', information_sousgroupe.sous_domaine)
        self.assertEqual(ts_groupe, information_sousgroupe.heure)
        self.assertEqual(ts_groupe + datetime.timedelta(hours=1), information_sousgroupe.heure_fin)
        self.assertEqual('collection_test', information_sousgroupe.nom_collection_mongo)
        self.assertEqual('/tmp/mgbackup/sousdomaine_test_2021011821.jsonl.xz', information_sousgroupe.path_fichier_backup)
        self.assertEqual('/tmp/mgbackup/sousdomaine_test_2021011821.json.xz', information_sousgroupe.path_fichier_catalogue)

        catalogue_backup = information_sousgroupe.catalogue_backup
        self.assertEqual('sousdomaine_test', catalogue_backup['domaine'])
        # self.assertEqual(Constantes.SECURITE_PUBLIC, catalogue_backup['securite'])
        self.assertEqual(ts_groupe, catalogue_backup['heure'])
        self.assertEqual('sousdomaine_test_2021011821.json.xz', catalogue_backup['catalogue_nomfichier'])
        self.assertEqual('sousdomaine_test_2021011821.jsonl.xz', catalogue_backup['transactions_nomfichier'])
        self.assertEqual(3, len(catalogue_backup['certificats_chaine_catalogue']))
        self.assertEqual(3, len(catalogue_backup['certificats_pem']))

    def test_preparation_backup_horaire_protege(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)

        clecert = self.contexte.configuration.cle
        info_cles = {
            'certificat': [clecert.cert_bytes.decode('utf-8')],
            'certificat_millegrille': clecert.chaine[-1],
            'certificats_backup': dict(),
        }

        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)
        information_sousgroupe.info_cles = info_cles

        self.handler_protege._preparation_backup_horaire(information_sousgroupe)

        # Verifications
        self.assertIsNotNone(information_sousgroupe.cipher)
        self.assertIsNotNone(information_sousgroupe.transaction_maitredescles)

        catalogue_backup = information_sousgroupe.catalogue_backup
        self.assertIsNotNone(catalogue_backup['iv'])
        self.assertIsNotNone(catalogue_backup['cle'])

    def test_preparation_backup_horaire_snapshot(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=True)

        self.handler_public._preparation_backup_horaire(information_sousgroupe)

        # Verification
        self.assertEqual('/tmp/mgbackup/sousdomaine_test_202101182100-SNAPSHOT.jsonl.xz', information_sousgroupe.path_fichier_backup)
        self.assertEqual('/tmp/mgbackup/sousdomaine_test_202101182100-SNAPSHOT.json.xz', information_sousgroupe.path_fichier_catalogue)

    def test_extraire_certificats(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        transaction = self.formatteur.signer_message({'valeur': 1})[0]

        # Call methode a tester
        resultat = self.handler_protege._extraire_certificats(transaction, ts_groupe)

        # Verification
        self.assertEqual(3, len(resultat))
        self.assertEqual(1, len(resultat['certificats']))
        self.assertEqual(1, len(resultat['certificats_intermediaires']))
        self.assertEqual(1, len(resultat['certificats_millegrille']))

    def test_persister_transactions_backup(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        fp = BytesIO()  # Simuler output fichier en memoire
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)
        information_sousgroupe.catalogue_backup = dict()

        # S'assurer que le certificat est dans le cache
        self.contexte.validateur_pki.valider(self.enveloppe_certificat.chaine_pem())

        # Data pour simuler transactions
        curseur = [
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
        ]

        # Call methode a tester
        self.handler_public._persister_transactions_backup(information_sousgroupe, curseur, fp)

        # Verification

        # Extraire transactions du contenu compresse en LZMA
        transactions_archivees = dict()
        bytes_ecrits = fp.getbuffer()
        with BytesIO(bytes_ecrits) as reader:
            lzma_file_object = LZMAFile(reader)
            for transaction_str in lzma_file_object:
                transaction = json.loads(transaction_str)
                transactions_archivees[transaction['valeur']] = transaction

        self.assertEqual(2, len(transactions_archivees))
        self.assertEqual(2, len(information_sousgroupe.uuid_transactions))

    def test_persister_transactions_backup_cipher(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        fp = BytesIO()  # Simuler output fichier en memoire
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)
        information_sousgroupe.catalogue_backup = dict()

        clecert = self.contexte.configuration.cle
        info_cles = {
            'certificat': [clecert.cert_bytes.decode('utf-8')],
            'certificat_millegrille': clecert.chaine[-1],
            'certificats_backup': dict(),
        }
        heure_str = '202101182100'
        cipher, transaction_maitrecles = self.backup_util.preparer_cipher(dict(), info_cles, heure_str)
        information_sousgroupe.cipher = cipher

        # S'assurer que le certificat est dans le cache
        self.contexte.validateur_pki.valider(self.enveloppe_certificat.chaine_pem())

        # Data pour simuler transactions
        curseur = [
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
        ]

        # Call methode a tester
        self.handler_protege._persister_transactions_backup(information_sousgroupe, curseur, fp)

        # Verification

        # Verifier que le contenu n'est pas en clair (LZMA invalide)
        bytes_ecrits = fp.getbuffer()
        with BytesIO(bytes_ecrits) as reader:
            lzma_file_object = LZMAFile(reader)
            self.assertRaises(LZMAError, lzma_file_object.read)

        self.assertEqual(2, len(information_sousgroupe.uuid_transactions))

    def test_marquer_transactions_backup_complete(self):
        uuid_transactions = ['a', 'b', 'c']
        self.handler_protege.marquer_transactions_backup_complete('collection_test', uuid_transactions)

        # Verification
        generateur_transactions = self.contexte.generateur_transactions
        messages = generateur_transactions.liste_emettre_message
        self.assertEqual(1, len(messages))
        evenement, domaine = messages[0]['args']
        self.assertEqual('evenement.TestDomaine.transactionEvenement', domaine)
        self.assertEqual('collection_test', evenement['domaine'])
        self.assertEqual('backup_horaire', evenement['evenement'])
        self.assertListEqual(uuid_transactions, evenement['uuid_transaction'])

    def test_marquer_transactions_invalides(self):
        uuid_transactions = ['a', 'b', 'c']
        self.handler_protege.marquer_transactions_invalides('collection_test', uuid_transactions)

        # Verification
        generateur_transactions = self.contexte.generateur_transactions
        messages = generateur_transactions.liste_emettre_message
        self.assertEqual(1, len(messages))
        evenement, domaine = messages[0]['args']
        self.assertEqual('evenement.TestDomaine.transactionEvenement', domaine)
        self.assertEqual('collection_test', evenement['domaine'])
        self.assertEqual('backup_erreur', evenement['evenement'])
        self.assertListEqual(uuid_transactions, evenement['uuid_transaction'])

    def test_transmettre_trigger_jour_precedent(self):
        ts = datetime.datetime(2021, 1, 18, 21, 0)
        self.handler_protege.transmettre_trigger_jour_precedent('test_transmettre_trigger_jour_precedent', ts)

        # Verification
        generateur_transactions = self.contexte.generateur_transactions
        evenement, domaine_action = generateur_transactions.liste_transmettre_commande[0]['args']
        self.assertEqual('commande.TestDomaine.declencherBackupQuotidien', domaine_action)
        self.assertEqual('TestDomaine', evenement['domaine'])
        self.assertLess(evenement['jour'], (ts-datetime.timedelta(days=1)).timestamp())
        self.assertGreater(evenement['jour'], (ts-datetime.timedelta(days=2)).timestamp())

    def test_transmettre_trigger_annee_precedente(self):
        ts = datetime.datetime(2021, 1, 18, 21, 0)
        self.handler_protege.transmettre_trigger_annee_precedente(ts, 'test_transmettre_trigger_annee_precedente')

        # Verification
        generateur_transactions = self.contexte.generateur_transactions
        evenement, domaine_action = generateur_transactions.liste_transmettre_commande[0]['args']
        self.assertEqual('commande.TestDomaine.declencherBackupAnnuel', domaine_action)
        self.assertEqual('TestDomaine', evenement['domaine'])
        self.assertLess(evenement['annee'], (ts-datetime.timedelta(days=549)).timestamp())
        self.assertGreater(evenement['annee'], (ts-datetime.timedelta(days=915)).timestamp())

    def test_calculer_hash_entetebackup(self):
        entete = {'valeur': 1}

        # Call methode a tester
        hachage = self.handler_protege.calculer_hash_entetebackup(entete)

        # Verifier
        self.assertEqual('sha256_b64:mljbzzAiBKFitVGyA6c9j/DEjIDFo3pxZX7t5sJmRZI=', hachage)

    def test_presister_catalogue(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        fp = StringIO()  # Simuler output fichier en memoire
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)
        information_sousgroupe.sha512_backup = 'hachage-catalogue'
        information_sousgroupe.path_fichier_backup = '/tmp/backup.jsonl'

        clecert = self.contexte.configuration.cle
        info_cles = {
            'certificat': [clecert.cert_bytes.decode('utf-8')],
            'certificat_millegrille': clecert.chaine[-1],
            'certificats_backup': dict(),
        }
        information_sousgroupe.info_cles = info_cles

        information_sousgroupe.catalogue_backup = {
            'certificats_millegrille': 'a',
            'certificats_intermediaires': 'b',
            'certificats': 'c',
            'fuuid_grosfichiers': 'd'
        }

        # Caller methode a tester
        self.handler_protege.persister_catalogue(information_sousgroupe, fp)

        catalogue_str = fp.getvalue()
        catalogue = json.loads(catalogue_str)

        self.assertEqual('a', catalogue['certificats_millegrille'])
        self.assertEqual('b', catalogue['certificats_intermediaires'])
        self.assertEqual('c', catalogue['certificats'])
        self.assertEqual('d', catalogue['fuuid_grosfichiers'])
        self.assertEqual('hachage-catalogue', catalogue['transactions_hachage'])
        self.assertEqual('backup.jsonl', catalogue['transactions_nomfichier'])

    def test_preparer_catalogue(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)
        information_sousgroupe.path_fichier_catalogue = '/tmp/catalogue.json'
        information_sousgroupe.path_fichier_backup = '/tmp/backup.jsonl'

        # Caller methode
        catalogue = self.handler_protege.preparer_catalogue(information_sousgroupe)

        # Verification
        self.assertEqual('sousdomaine_test', catalogue['domaine'])
        # self.assertEqual('3.protege', catalogue['securite'])
        self.assertIsNotNone(catalogue['heure'])
        self.assertEqual('catalogue.json', catalogue['catalogue_nomfichier'])
        self.assertEqual('backup.jsonl', catalogue['transactions_nomfichier'])
        self.assertEqual(3, len(catalogue['certificats_chaine_catalogue']))
        self.assertEqual(3, len(catalogue['certificats_pem']))

    def test_uploader_fichiers_backup(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)
        information_sousgroupe.path_fichier_backup = '/tmp/backup.jsonl'
        information_sousgroupe.path_fichier_catalogue = '/tmp/catalogue.json'
        information_sousgroupe.catalogue_backup = {
            ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE: 'allo',
        }

        # Simuler fichiers en memoire
        fp_backup = BytesIO()
        fp_catalogue = BytesIO()

        # Caller methode a tester
        self.handler_protege.uploader_fichiers_backup(information_sousgroupe, fp_backup, fp_catalogue)

        # Verification resultats
        requests_call = self._requests_calls[0]
        data = requests_call['kwargs']['data']
        files = requests_call['kwargs']['files']
        verify = requests_call['kwargs']['verify']
        cert = requests_call['kwargs']['cert']

        self.assertEqual('https://fichiers:443/backup/domaine/catalogue.json', requests_call['args'][0])
        self.assertEqual(cert, (
            '/usr/local/etc/millegrilles/certs/pki.millegrilles.ssl.cert',
            '/usr/local/etc/millegrilles/keys/pki.millegrilles.ssl.key'
        ))
        self.assertDictEqual(data, {'timestamp_backup': 1611003600})
        self.assertEqual('/opt/millegrilles/etc/millegrilles.RootCA.pem', verify)
        self.assertEqual(('backup.jsonl', fp_backup, 'application/x-xz'), files['transactions'])
        self.assertEqual(('catalogue.json', fp_catalogue, 'application/x-xz'), files['catalogue'])

    def test_soumettre_transactions_backup_horaire(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)
        information_sousgroupe.catalogue_backup = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE: {
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: 'DUMMY'
            },
            'securite': '3.protege',
        }

        # Caller methode a tester
        self.handler_protege.soumettre_transactions_backup_horaire(information_sousgroupe)

        # Verifications
        evenement = self.contexte.generateur_transactions.liste_emettre_message[0]
        transaction_catalogue = self.contexte.generateur_transactions.liste_relayer_transactions[0]
        transaction_hachage = self.contexte.generateur_transactions.liste_soumettre_transaction[0]

        self.assertDictEqual(transaction_catalogue['args'][0], information_sousgroupe.catalogue_backup)
        self.assertDictEqual(transaction_hachage['args'][0], {
            'domaine': 'sousdomaine_test',
            # 'securite': '3.protege',
            'heure': 1611003600,
            'catalogue_hachage': None,
            'hachage_entete': 'sha256_b64:T87zS0qkcWmB6xvCFENW0puNff7mGb2QVgx/G+ITKkg=',
            'uuid_transaction': 'DUMMY'
        })
        self.assertEqual('Backup.catalogueHoraireHachage', transaction_hachage['args'][1])
        self.assertDictEqual(evenement['args'][0], {
            '_evenements': 'evenement',
            'uuid_transaction': [],
            'domaine': 'TestTransactions',
            'evenement': 'backup_horaire'
        })
        self.assertEqual('evenement.TestDomaine.transactionEvenement', evenement['args'][1])

    def test_creer_backup_quoditien(self):
        ts = datetime.datetime(2021, 1, 18, 21, 0)

        document_dao = self.contexte.document_dao
        document_dao.valeurs_find.append([{
            'jour': datetime.datetime(2021, 1, 17, 1, 0)
        }])

        # Caller methode a tester
        self.handler_protege.creer_backup_quoditien('sousdomaine_test', ts, 'test_creer_backup_quoditien')

        # Verifications
        calls_find = document_dao.calls_find
        info_commande_quotidien = self.contexte.generateur_transactions.liste_transmettre_commande[0]
        info_commande_annuel = self.contexte.generateur_transactions.liste_transmettre_commande[1]

        self.assertDictEqual(info_commande_annuel['args'][0], {
            'annee': 1546300800,
            'domaine': 'TestDomaine',
            'uuid_rapport': 'test_creer_backup_quoditien',
        })
        self.assertEqual('commande.TestDomaine.declencherBackupAnnuel', info_commande_annuel['args'][1])
        self.assertDictEqual(info_commande_quotidien['args'][0], {
            'catalogue': {'jour': 1610845200, 'en-tete': {'uuid_transaction': 'dummy.0'}},
            'uuid_rapport': 'test_creer_backup_quoditien'
        })
        self.assertEqual('commande.backup.genererBackupQuotidien', info_commande_quotidien['args'][1])

    def test_creer_backup_annuel(self):
        ts = datetime.datetime(2020, 8, 18, 21, 0)

        document_dao = self.contexte.document_dao
        document_dao.valeurs_find.append([{
            'annee': datetime.datetime(2020, 1, 17, 0, 0)
        }])

        # Caller methode a tester
        self.handler_protege.creer_backup_annuel('sousdomaine_test', ts, 'test_creer_backup_annuel')

        # Verifications
        calls_find = document_dao.calls_find
        info_commande_annuel = self.contexte.generateur_transactions.liste_transmettre_commande[0]

        self.assertDictEqual(info_commande_annuel['args'][0], {
            'catalogue': {'annee': 1579219200, 'en-tete': {'uuid_transaction': 'dummy.0'}},
            'uuid_rapport': 'test_creer_backup_annuel'
        })
        self.assertEqual('commande.backup.genererBackupAnnuel', info_commande_annuel['args'][1])


class HandlerBackupGrosFichiersTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()

        self.handler_grosfichiers_protege = HandlerBackupGrosFichiers(self.contexte)

        self.backup_util = BackupUtil(self.contexte)

        self.enveloppe_certificat = self.contexte.validateur_pki.valider(self.contexte.configuration.cle.chaine)
        idmg = self.enveloppe_certificat.subject_organization_name
        self.formatteur = FormatteurMessageMilleGrilles(idmg, self.contexte.signateur_transactions)

        self.contexte.generateur_transactions.reset()

        self._requests_calls = list()
        self._requests_response = RequestsReponse()

    def test_extraire_certificats_none(self):
        ts = datetime.datetime(2021, 1, 18, 21, 0)
        transaction = self.formatteur.signer_message({
            'valeur': 1
        }, 'dummy_domaine')[0]

        # Caller methode a tester
        resultat = self.handler_grosfichiers_protege._extraire_certificats(transaction, ts)

        # Verifications
        self.assertEqual(0, len(resultat['fuuid_grosfichiers']))
        self.assertListEqual(['sha256_b64:VAbbqvSU4Iq1+/ajwcc4nklWFkPrcuPsWHuHUe59Cb8='], resultat['certificats_millegrille'])
        self.assertEqual(1, len(resultat['certificats']))
        self.assertEqual(1, len(resultat['certificats_intermediaires']))

    def test_extraire_certificats_nouvelleversion(self):
        ts = datetime.datetime(2021, 1, 18, 21, 0)
        transaction = self.formatteur.signer_message({
            ConstantesGrosFichiers.DOCUMENT_SECURITE: '3.protege',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE: 'hachage_1',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER: 'fichier_1.txt',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: 'abcd-1234-efgh-5678',
        }, ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_METADATA)[0]

        # Caller methode a tester
        resultat = self.handler_grosfichiers_protege._extraire_certificats(transaction, ts)

        # Verifications
        self.assertDictEqual(resultat['fuuid_grosfichiers'], {
            'abcd-1234-efgh-5678': {'securite': '3.protege', 'hachage': 'hachage_1', 'extension': 'txt', 'heure': '21'}
        })
        self.assertListEqual(['sha256_b64:VAbbqvSU4Iq1+/ajwcc4nklWFkPrcuPsWHuHUe59Cb8='], resultat['certificats_millegrille'])
        self.assertEqual(1, len(resultat['certificats']))
        self.assertEqual(1, len(resultat['certificats_intermediaires']))

    def test_extraire_certificats_associerpreview(self):
        ts = datetime.datetime(2021, 1, 18, 21, 0)
        transaction = self.formatteur.signer_message({
            ConstantesGrosFichiers.DOCUMENT_SECURITE: '3.protege',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE_PREVIEW: 'hachage_1',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_PREVIEW: 'txt',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW: 'abcd-1234-efgh-5678',
        }, ConstantesGrosFichiers.TRANSACTION_ASSOCIER_PREVIEW)[0]

        # Caller methode a tester
        resultat = self.handler_grosfichiers_protege._extraire_certificats(transaction, ts)

        # Verifications
        self.assertDictEqual(resultat['fuuid_grosfichiers'], {
            'abcd-1234-efgh-5678': {'securite': '3.protege', 'hachage': 'hachage_1', 'extension': 'txt', 'heure': '21'}
        })
        self.assertListEqual(['sha256_b64:VAbbqvSU4Iq1+/ajwcc4nklWFkPrcuPsWHuHUe59Cb8='], resultat['certificats_millegrille'])
        self.assertEqual(1, len(resultat['certificats']))
        self.assertEqual(1, len(resultat['certificats_intermediaires']))


class HandlerBackupMaitreDesClesTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()

        self.handler_maitredescles_protege = HandlerBackupMaitreDesCles(self.contexte)

        self.backup_util = BackupUtil(self.contexte)

        self.enveloppe_certificat = self.contexte.validateur_pki.valider(self.contexte.configuration.cle.chaine)
        idmg = self.enveloppe_certificat.subject_organization_name
        self.formatteur = FormatteurMessageMilleGrilles(idmg, self.contexte.signateur_transactions)

        self.contexte.generateur_transactions.reset()

        self._requests_calls = list()
        self._requests_response = RequestsReponse()

    def test_persister_transactions_backup(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        fp = BytesIO()  # Simuler output fichier en memoire
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)
        information_sousgroupe.catalogue_backup = dict()

        # S'assurer que le certificat est dans le cache
        self.contexte.validateur_pki.valider(self.enveloppe_certificat.chaine_pem())

        # Data pour simuler transactions
        curseur = [
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
        ]

        # Call methode a tester
        self.handler_maitredescles_protege._persister_transactions_backup(information_sousgroupe, curseur, fp)

        # Verification

        # Extraire transactions du contenu compresse en LZMA
        transactions_archivees = dict()
        bytes_ecrits = fp.getbuffer()
        with BytesIO(bytes_ecrits) as reader:
            lzma_file_object = LZMAFile(reader)
            for transaction_str in lzma_file_object:
                transaction = json.loads(transaction_str)
                transactions_archivees[transaction['valeur']] = transaction

        self.assertEqual(2, len(transactions_archivees))
        self.assertEqual(2, len(information_sousgroupe.uuid_transactions))

    def test_preparation_backup_horaire(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)

        self.handler_maitredescles_protege._preparation_backup_horaire(information_sousgroupe)

        # Verification
        self.assertEqual('sousdomaine_test', information_sousgroupe.sous_domaine)
        self.assertEqual(ts_groupe, information_sousgroupe.heure)
        self.assertEqual(ts_groupe + datetime.timedelta(hours=1), information_sousgroupe.heure_fin)
        self.assertEqual('collection_test', information_sousgroupe.nom_collection_mongo)
        self.assertEqual('/tmp/ut_backupmoduletest/sousdomaine_test_2021011821.jsonl.xz', information_sousgroupe.path_fichier_backup)
        self.assertEqual('/tmp/ut_backupmoduletest/sousdomaine_test_2021011821.json.xz', information_sousgroupe.path_fichier_catalogue)


class HandlerBackupDomaine_FileIntegrationTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()

        self.handler_protege = HandlerBackupDomaine(
            self.contexte, "TestDomaine", "TestTransactions", "TestDocuments",
            niveau_securite=Constantes.SECURITE_PROTEGE
        )
        self.handler_public = HandlerBackupDomaine(
            self.contexte, "TestDomaine", "TestTransactions", "TestDocuments",
            niveau_securite=Constantes.SECURITE_PUBLIC
        )
        self.backup_util = BackupUtil(self.contexte)

        self.enveloppe_certificat = self.contexte.validateur_pki.valider(self.contexte.configuration.cle.chaine)
        idmg = self.enveloppe_certificat.subject_organization_name
        self.formatteur = FormatteurMessageMilleGrilles(idmg, self.contexte.signateur_transactions)

        self.files_for_cleanup = list()

        # Override methode requests
        self.handler_protege._requests_put = self.__requests_put
        self.handler_public._requests_put = self.__requests_put

        self._requests_calls = list()
        self._requests_response = RequestsReponse()

        self.extract_samples = True

    def tearDown(self) -> None:
        super().tearDown()

        for f in self.files_for_cleanup:
            try:
                os.unlink(f)
            except FileNotFoundError:
                pass # OK
            except Exception:
                self.logger.exception("Erreur nettoyage fichier")

    def __requests_put(self, *args, **kwargs):
        self.logger.info("CALL requests_put:\n%s\n%s" % (args, kwargs))
        self._requests_calls.append({
            'args': args,
            'kwargs': kwargs,
        })

        try:
            test_params = kwargs['test_params']
            information_sousgroupe = test_params['information_sousgroupe']
        except (KeyError, TypeError):
            pass  # OK Pas de valeur
        else:
            fichiers_domaine = self._requests_response.json['fichiersDomaines']
            fichiers_domaine[information_sousgroupe.nom_fichier_backup] = information_sousgroupe.sha512_backup

        return self._requests_response

    def test_execution_backup_horaire(self):
        ts_groupe = datetime.datetime(2021, 1, 18, 21, 0)
        information_sousgroupe = InformationSousDomaineHoraire(
            'collection_test', 'sousdomaine_test', ts_groupe, snapshot=False)

        information_sousgroupe.path_fichier_catalogue = '/tmp/catalogue.json'
        information_sousgroupe.path_fichier_backup = '/tmp/backup.jsonl'

        document_dao = self.contexte.document_dao

        # Preparer transactions pour le backup
        document_dao.valeurs_find.append([
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
            self.formatteur.signer_message({'valeur': 3})[0],
        ])

        self.files_for_cleanup.extend([
            information_sousgroupe.path_fichier_catalogue,
            information_sousgroupe.path_fichier_backup,
        ])

        clecert = self.contexte.configuration.cle
        info_cles = {
            'certificat': [clecert.cert_bytes.decode('utf-8')],
            'certificat_millegrille': clecert.chaine[-1],
            'certificats_backup': dict(),
        }
        information_sousgroupe.info_cles = info_cles

        information_sousgroupe.catalogue_backup = {
            'certificats_millegrille': set(),
            'certificats_intermediaires': set(),
            'certificats': set(),
            'fuuid_grosfichiers': set()
        }

        # Caller methode a tester
        self.handler_protege._execution_backup_horaire(information_sousgroupe)

        # Verifier contenu
        backup_transactions = list()
        with lzma.open(information_sousgroupe.path_fichier_backup, 'rt') as fichier:
            l = fichier.readline()
            while l:
                backup_transactions.append(json.loads(l))
                l = fichier.readline()
        with lzma.open(information_sousgroupe.path_fichier_catalogue, 'rt') as fichier:
            catalogue = json.load(fichier)

        self.assertEqual(1, backup_transactions[0]['valeur'])
        self.assertEqual(2, backup_transactions[1]['valeur'])
        self.assertEqual(3, backup_transactions[2]['valeur'])
        self.assertEqual('backup.jsonl', catalogue['transactions_nomfichier'])
        self.assertIsNotNone(catalogue['transactions_hachage'])
        self.assertIsNotNone(information_sousgroupe.sha512_catalogue)

        if self.extract_samples:
            with open(information_sousgroupe.path_fichier_backup, 'rb') as fichier:
                sample = b64encode(fichier.read()).decode('utf-8')
                self.logger.info("SAMPLE - TRANSACTIONS test_execution_backup_horaire\n%s" % sample)
            with open(information_sousgroupe.path_fichier_catalogue, 'rb') as fichier:
                sample = b64encode(fichier.read()).decode('utf-8')
                self.logger.info("SAMPLE - CATALOGUE test_execution_backup_horaire\n%s" % sample)

    def test_backup_horaire_domaine_1domaine(self):
        ts = datetime.datetime(2021, 1, 19, 0, 2)
        info_cles: Optional[dict] = None

        contexte = self.contexte
        configuration = contexte.configuration
        configuration.backup_workdir = '/tmp/ut_backupmoduletest'
        document_dao = contexte.document_dao

        ts_1 = datetime.datetime(2021, 1, 18, 22, 0)
        document_dao.valeurs_aggregate.append([
            {'_id': {'timestamp': ts_1}, 'sousdomaine': [['sousdomaine_test', 'abcd', '1234']], 'count': 7},
        ])
        document_dao.valeurs_find.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup
        document_dao.valeurs_find.append([
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
            self.formatteur.signer_message({'valeur': 3})[0],
        ])

        self._requests_response.json = {
            'fichiersDomaines': dict(),
            'ok': True
        }

        # Caller methode a tester
        self.handler_public.backup_horaire_domaine('test_backup_horaire_domaine_1domaine', ts, info_cles, supprimer_temp=False)

        # Preparation au nettoyage
        generateur_transactions = self.contexte.generateur_transactions
        info_transaction_catalogue = generateur_transactions.liste_relayer_transactions[0]
        transaction_catalogue = info_transaction_catalogue['args'][0]
        fichiers = [os.path.join(configuration.backup_workdir, f) for f in [
            transaction_catalogue['transactions_nomfichier'],
            transaction_catalogue['catalogue_nomfichier'],
        ]]
        self.files_for_cleanup.extend(fichiers)

        # Verifications

        # On verifie les fichiers non-chiffres sauvegardes sur disque
        catalogues = list()
        for f in fichiers:
            with lzma.open(f, 'rt') as fichier:
                for l in fichier:
                    contenu = json.loads(l)

                    # Conserver catalogue pour test additionnel
                    if f.endswith('.json.xz'):
                        catalogues.append(contenu)

                    try:
                        self.contexte.validateur_message.verifier(contenu)
                    except KeyError as e:
                        # OK si on a une entete generee par le contexte UT
                        if not contenu['en-tete']['uuid_transaction'].startswith('dummy.'):
                            raise e

        # On verifie le chainage des catalogues
        self.assertEqual(1, len(catalogues))
        self.assertIsNone(catalogues[0]['backup_precedent'])

        if self.extract_samples:
            with open(os.path.join(configuration.backup_workdir, transaction_catalogue['transactions_nomfichier']), 'rb') as fichier:
                sample = b64encode(fichier.read()).decode('utf-8')
                self.logger.info("SAMPLE - TRANSACTIONS test_execution_backup_horaire\n%s" % sample)
            with open(os.path.join(configuration.backup_workdir, transaction_catalogue['catalogue_nomfichier']), 'rb') as fichier:
                sample = b64encode(fichier.read()).decode('utf-8')
                self.logger.info("SAMPLE - CATALOGUE test_execution_backup_horaire\n%s" % sample)

    def test_backup_horaire_domaine_1domaine_chainage(self):
        ts = datetime.datetime(2021, 1, 19, 0, 2)
        info_cles = None

        contexte = self.contexte
        configuration = contexte.configuration
        configuration.backup_workdir = '/tmp/ut_backupmoduletest'
        document_dao = contexte.document_dao

        ts_1 = datetime.datetime(2021, 1, 18, 20, 0)
        ts_2 = datetime.datetime(2021, 1, 18, 21, 0)
        ts_3 = datetime.datetime(2021, 1, 18, 22, 0)
        document_dao.valeurs_aggregate.append([
            {'_id': {'timestamp': ts_1}, 'sousdomaine': [['sousdomaine_test', 'abcd', '1234']], 'count': 7},
            {'_id': {'timestamp': ts_2}, 'sousdomaine': [['sousdomaine_test', 'abcd', '1234']], 'count': 3},
            {'_id': {'timestamp': ts_3}, 'sousdomaine': [['sousdomaine_test', 'abcd', '1234']], 'count': 5},
        ])
        document_dao.valeurs_find.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup, 3 groupes pour test de chainage
        document_dao.valeurs_find.append([self.formatteur.signer_message({'valeur': 1})[0]])
        document_dao.valeurs_find.append([self.formatteur.signer_message({'valeur': 2})[0]])
        document_dao.valeurs_find.append([self.formatteur.signer_message({'valeur': 3})[0]])

        self._requests_response.json = {
            'fichiersDomaines': dict(),
            'ok': True,
        }

        # Caller methode a tester
        self.handler_public.backup_horaire_domaine('test_backup_horaire_domaine_1domaine_chainage', ts, info_cles, supprimer_temp=False)

        # Preparation au nettoyage
        generateur_transactions = self.contexte.generateur_transactions
        for info_transaction_catalogue in generateur_transactions.liste_relayer_transactions:
            transaction_catalogue = info_transaction_catalogue['args'][0]
            fichiers = [os.path.join(configuration.backup_workdir, f) for f in [
                transaction_catalogue['transactions_nomfichier'],
                transaction_catalogue['catalogue_nomfichier'],
            ]]
            self.files_for_cleanup.extend(fichiers)

        # Verifications

        # On verifie les fichiers non-chiffres sauvegardes sur disque
        catalogues = list()
        for f in self.files_for_cleanup:
            with lzma.open(f, 'rt') as fichier:
                for l in fichier:
                    contenu = json.loads(l)

                    # Conserver catalogue pour test additionnel
                    if f.endswith('.json.xz'):
                        catalogues.append(contenu)

                    try:
                        self.contexte.validateur_message.verifier(contenu)
                    except KeyError as e:
                        # OK si on a une entete generee par le contexte UT
                        if not contenu['en-tete']['uuid_transaction'].startswith('dummy.'):
                            raise e

        # On verifie le chainage des catalogues, hachage des entetes
        self.assertEqual(3, len(catalogues))
        self.assertIsNone(catalogues[0]['backup_precedent'])
        self.assertDictEqual(catalogues[1]['backup_precedent'], {
            'hachage_entete': 'sha256_b64:EsMUl/S7JTgOBTPbhogyCTVuzCpn3xfA7hgCmSMwoWs=', 'uuid_transaction': 'dummy.0'
        })
        self.assertDictEqual(catalogues[2]['backup_precedent'], {
            'hachage_entete': 'sha256_b64:pyVbBs8ujea0IHi5k9KevV8x0Y+2oHxtoKJEzkUdKJM=', 'uuid_transaction': 'dummy.1'
        })

    def test_backup_horaire_domaine_protege(self):
        ts = datetime.datetime(2021, 1, 19, 0, 2)
        clecert = self.contexte.configuration.cle
        info_cles = {
            'certificat': [clecert.cert_bytes.decode('utf-8')],
            'certificat_millegrille': clecert.chaine[-1],
            'certificats_backup': dict(),
        }

        contexte = self.contexte
        configuration = contexte.configuration
        configuration.backup_workdir = '/tmp/ut_backupmoduletest'
        document_dao = contexte.document_dao

        ts_1 = datetime.datetime(2021, 1, 18, 22, 0)
        document_dao.valeurs_aggregate.append([
            {'_id': {'timestamp': ts_1}, 'sousdomaine': [['sousdomaine_test', 'abcd', '1234']], 'count': 7},
        ])
        document_dao.valeurs_find.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup
        document_dao.valeurs_find.append([
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
            self.formatteur.signer_message({'valeur': 3})[0],
        ])

        self._requests_response.json = {
            'fichiersDomaines': dict(),
            'ok': True,
        }

        # Caller methode a tester
        self.handler_protege.backup_horaire_domaine('test_backup_horaire_domaine_protege', ts, info_cles, supprimer_temp=False)

        # Preparation au nettoyage
        generateur_transactions = self.contexte.generateur_transactions
        info_transaction_catalogue = generateur_transactions.liste_relayer_transactions[0]
        transaction_catalogue = info_transaction_catalogue['args'][0]
        fichiers = [os.path.join(configuration.backup_workdir, f) for f in [
            transaction_catalogue['transactions_nomfichier'],
            transaction_catalogue['catalogue_nomfichier'],
        ]]
        self.files_for_cleanup.extend(fichiers)

        # Verifications

        # On verifie les fichiers sauvegardes sur disque
        catalogues = list()
        for f in fichiers:
            with lzma.open(f, 'rt') as fichier:
                if f.endswith('.mgs1'):
                    # S'assurer que le fichier de backup n'est pas "lisible"
                    self.assertRaises(LZMAError, fichier.read)
                else:
                    contenu = json.loads(fichier.read())
                    catalogues.append(contenu)

        # On verifie le chainage des catalogues
        self.assertEqual(1, len(catalogues))
        self.assertIsNone(catalogues[0]['backup_precedent'])

    def test_backup_horaire_domaine_snapshot(self):
        ts = datetime.datetime(2021, 1, 19, 0, 2)
        info_cles: Optional[dict] = None

        contexte = self.contexte
        configuration = contexte.configuration
        configuration.backup_workdir = '/tmp/ut_backupmoduletest'
        document_dao = contexte.document_dao

        ts_1 = datetime.datetime(2021, 1, 18, 22, 0)
        document_dao.valeurs_aggregate.append([
            {'_id': {'timestamp': ts_1}, 'sousdomaine': [['sousdomaine_test', 'abcd', '1234']], 'count': 7},
        ])
        document_dao.valeurs_find.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup
        document_dao.valeurs_find.append([
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
            self.formatteur.signer_message({'valeur': 3})[0],
        ])

        self._requests_response.json = {
            'fichiersDomaines': dict(),
            'ok': True,
        }

        # Caller methode a tester
        self.handler_public.backup_horaire_domaine('test_backup_horaire_domaine_snapshot', ts, info_cles, snapshot=True, supprimer_temp=False)

        # Preparation au nettoyage
        generateur_transactions = self.contexte.generateur_transactions
        self.assertEqual(0, len(generateur_transactions.liste_relayer_transactions))

        # Charger fichiers a partir du repertoire
        fichiers = list()
        for f in os.listdir(configuration.backup_workdir):
            fichiers.append(os.path.join(configuration.backup_workdir, f))
        self.files_for_cleanup.extend(fichiers)

        # Verifications
        self.assertEqual(2, len(fichiers))

        # On verifie les fichiers non-chiffres sauvegardes sur disque
        catalogues = list()
        for f in fichiers:
            self.assertGreater(f.find('SNAPSHOT'), 0)

            with lzma.open(f, 'rt') as fichier:
                for l in fichier:
                    contenu = json.loads(l)

                    # Conserver catalogue pour test additionnel
                    if f.endswith('.json.xz') > 0:
                        catalogues.append(contenu)

                    try:
                        self.contexte.validateur_message.verifier(contenu)
                    except KeyError as e:
                        # OK si on a une entete generee par le contexte UT
                        if not contenu['en-tete']['uuid_transaction'].startswith('dummy.'):
                            raise e

        # On verifie le chainage des catalogues
        self.assertEqual(1, len(catalogues))
        self.assertIsNone(catalogues[0]['backup_precedent'])

    def test_backup_horaire_domaine_messages_ok(self):
        ts = datetime.datetime(2021, 1, 19, 0, 2)
        info_cles: Optional[dict] = None

        contexte = self.contexte
        configuration = contexte.configuration
        configuration.backup_workdir = '/tmp/ut_backupmoduletest'
        document_dao = contexte.document_dao

        ts_1 = datetime.datetime(2021, 1, 18, 22, 0)
        document_dao.valeurs_aggregate.append([
            {'_id': {'timestamp': ts_1}, 'sousdomaine': [['sousdomaine_test', 'abcd', '1234']], 'count': 7},
        ])
        document_dao.valeurs_find.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup
        document_dao.valeurs_find.append([
            self.formatteur.signer_message({'valeur': 1})[0],
        ])

        self._requests_response.json = {
            'fichiersDomaines': dict(),
            'ok': True
        }

        # Caller methode a tester
        self.handler_public.backup_horaire_domaine('test_backup_horaire_domaine_messages_ok', ts, info_cles, supprimer_temp=False)

        # Preparation au nettoyage
        generateur_transactions = self.contexte.generateur_transactions
        info_transaction_catalogue = generateur_transactions.liste_relayer_transactions[0]
        transaction_catalogue = info_transaction_catalogue['args'][0]
        fichiers = [os.path.join(configuration.backup_workdir, f) for f in [
            transaction_catalogue['transactions_nomfichier'],
            transaction_catalogue['catalogue_nomfichier'],
        ]]
        self.files_for_cleanup.extend(fichiers)

        # Verifications
        evenements = [e['args'][0] for e in generateur_transactions.liste_emettre_message]
        self.assertDictEqual(evenements[0], {
            'evenement': 'backupHoraireDebut',
            ConstantesBackup.CHAMP_UUID_RAPPORT: 'test_backup_horaire_domaine_messages_ok',
            'domaine': 'TestDomaine',
            'timestamp': 1611014520,
            'securite': '1.public'
        })
        self.assertDictEqual(evenements[1], {
            'evenement': 'backupHoraireDebut',
            ConstantesBackup.CHAMP_UUID_RAPPORT: 'test_backup_horaire_domaine_messages_ok',
            'domaine': 'sousdomaine_test.abcd.1234',
            'timestamp': 1611014520,
            'securite': '1.public'
        })
        self.assertDictEqual(evenements[3], {
            'evenement': 'backupHoraireTermine',
            ConstantesBackup.CHAMP_UUID_RAPPORT: 'test_backup_horaire_domaine_messages_ok',
            'domaine': 'sousdomaine_test.abcd.1234',
            'timestamp': 1611014520,
            'securite': '1.public'
        })
        self.assertDictEqual(evenements[4], {
            'evenement': 'backupHoraireTermine',
            ConstantesBackup.CHAMP_UUID_RAPPORT: 'test_backup_horaire_domaine_messages_ok',
            'domaine': 'TestDomaine',
            'timestamp': 1611014520,
            'securite': '1.public'
        })

        # {'_evenements': 'evenement', 'uuid_transaction': ['53d584a0-6712-11eb-8353-2987badbfc4c', '53d584a1-6712-11eb-8353-2987badbfc4c', '53d584a2-6712-11eb-8353-2987badbfc4c'], 'domaine': 'TestTransactions', 'evenement': 'backup_horaire'}
        self.assertEqual(evenements[2]['domaine'], 'TestTransactions')
        self.assertEqual(1, len(evenements[2]['uuid_transaction']))

        quotidien = generateur_transactions.liste_transmettre_commande[0]
        quotidien_message = quotidien['args'][0]
        quotidien_rk = quotidien['args'][1]
        quotidien_exchange = quotidien['kwargs']['exchange']

        self.assertEqual(quotidien_rk,  'commande.TestDomaine.declencherBackupQuotidien')
        self.assertEqual(quotidien_exchange, Constantes.SECURITE_SECURE)
        self.assertDictEqual(
            quotidien_message,
            {'jour': 1610841600, 'domaine': 'TestDomaine', 'uuid_rapport': 'test_backup_horaire_domaine_messages_ok'}
        )


class ArchivesBackupParserTest(TestCaseContexte):

    # Sample de fichiers de transactions (lzma, jsonl)
    SAMPLE_TRANSACTIONS_NOMS = [
        'sousdomaine_test.abcd.1234_transactions_2021011822_1.public.jsonl.xz'
    ]
    SAMPLE_TRANSACTIONS = [
        b'/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4AhLBNBdAD2Ih+czhTwcCpsSCGl+NG1qsR8phvfJrI1mppgJn0P2exSGquKcnwa0bdxuqOGOywrNw'
        b'ZsXVGuGdyli9tqqrbnOJZ3SYj9FC8O2JZuhjXT1PzOCr1Qc+nNhV+Zl43z07j2UgLXO69jyk7wciupR7rx9yEfc9MQyiYBJqJYPhXDCZu/f/5'
        b'BhUum+yGj4i6opSgGw0wnUjIj0SwpPu+ccuYXCq/2cpFbwiSjDRPAXVLBguGFlHhyCVhwGjIl4xrwmMjn02WPBXtwuzlIPdKfiQCuW8VY2LPA'
        b'IbUT04nYGI+ToZI3ywhb/O4xGcUUO/oTVyq3pOoRn4FzXWDtLsJA98pEP8KVhhO4AnPinhazvkMdBLd8zyO6ZNL0dv46I+rwBCOAFDcUoXASJ'
        b'ksfUwtDqPuJQGR1yGQnAP0MYHsLbqbbu8ppKJ0yjbCK/LemCb8zg6YbrRzDbkKt8+9l7fxqx1vykXeUmkUTJr5K2R3Ey4GxO4KZBApbmhHZKW'
        b'5uqhiXryBFUg7nOLe8FLvKNCth5HkXNmiVrjRDcCwCf2T4k0pAfjAa/hd3XE9FKlvvFELxMFcJJ+suLnJSqf3d87MkFsh+bUtLhRnBKLHkKVr'
        b'BEmzWrfcsL1OOGykjZaXLKWKT8GeejMv13xN++amZWES4oXCDTxTUJlzzT4bBLx/c0+CbvlqBtn8PpJ97OlZDQJ4uGiaLL2c2RViVfDLOMVoR'
        b'USEuZx9o1p2E3UDxqqe8+7o4zb4I4IUU5pOk6EUKN4lMa9ge3diC+1Px0Vgw/0dts4uNGVm/5LcvUaxgsLccxyfAOwwC9B1TAv6KQynCObssW'
        b'4L8tIGrDsLqi4XBG1b+v1NX7o1fGz1DCACe78zSzWWrz02bu0/HpL8Bd/MWeRRsCZAyuI8NKUUPSvt5XPEZBv54RxPTs8xMsVx0/gzgnITCe0'
        b'PfW3ntTDHWfcKSsu5Z8WRcQl7uTqroKEjyBmbsBWsqXLnkFTKK7XRgaCvC20t/VqkqmaZ9iG7EvvbgmufCm3OiY+I2mrrPUAkR4baM4lXiz3T'
        b'+Ti/XHm4bucs0UzNp+5vJVB7Qe3XOxlgKkrkHtk3stqOUgaSKM49nKcEhU9FrVy90Q/GNY20BpcmpPB7yjJuE1VqJbfgF8gLh0VHkuM5GSGOW'
        b'5p/duMJBNMMC9Ang8K3r2w8Se3qyLG+oJwvlvTcXJSaz+CXqvP2lqvpiCtdGL31Vco+jxD/ZjMP2Ag8iHDKA4jpC7TqV1dFCqCL1XQZwRZbh1'
        b'pONTQkxx51B7ZFFu5RB3ToKBKyZtB0Rl+POWHRI8IG4vE10gxqKpQxZRxCJ7y2pn5Y7AXpFFWZqDVJwV06svxw1RvJ+kvtmWue8/BmHOzW8jm'
        b'jZWQk+B9N73oxqNvZmsvEP1gPfumWdPQ3URgzTDANrScvyfn2OHEXDvm7ou/IQoyv7T3OK84Tna4JU8ILJx0pJpPkZk1VV/EBve/+FyNZQ1rU'
        b'2VL589ZgeGZBsvIU2D2PV/Z2nwMQ1MYKwSnXBNEHbbPTiIeXZMwl86uAb2oJdXlLhyYNQPZ3NyxiSbmmBzLSlmusngoBH25GztgvnptauLt0a'
        b'sQXyVnBEz5jFxZs0qAI85V9DGCynulxYdiQ7RAnaTvUN0WCwAAE58p9DPSXfAAAHsCcwQAACbn36PscRn+wIAAAAABFla',
    ]

    # Sample de fichiers de catalogues (lzma, json)
    SAMPLE_CATALOGUES_NOMS = [
        'sousdomaine_test.abcd.1234_catalogue_2021011822_1.public.json.xz'
    ]
    SAMPLE_CATALOGUES = [
        b'/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4Bh/D6hdAD2IiEZT2x5VkgSmO0tZm2FK2Yxpu8kQ/XurG1PvO9+JH1WoUKJyQoW04CoYUYTLzfgF8'
        b'XvmW96oPPnfn/JCerE0JA3zpQ0W9n4NGfWUaxDh9hqVgnCMN/Fw+y9F5Lxzwfvg8yEZK+rYxfnAScLI3WHGK2bqW2UXjYW1k3fZ59k6OI6VRf'
        b'y/pVUa/ljfr/EZhI6bbn4M+gmRBCHDM5Dw8hPu1rsWstpbeeBQ8Qq7FSGBWBigPX8eYjspycJ0N+AF75KnANpOTdUODwNFgUXO1KDV2LfIza+'
        b'l+15uwsdjkb+5e7Pct1KSusxruIJNF7OWTa19B3DO/bV2d81O6Wn6gTBmwmMCyH/uJaZdICaJ56mE+VSaXv//zUpPtUw+GHwuSBtFXkrx4KY6'
        b'QPqsVQVMQroDOkNhN1urT0vDGuPAfQpmj40YQdk5tbUHQyHzbJMPu9d2QHs9KCsUiZCZyP63P6Hib1xGofq4S3jAYgrQSzgtaWvRjt1lhN/lf'
        b'7ChJLqe8Llri+HHYACNUrzwdVKz5DqGu8lF3MqULJxJY+FIGVBk1B6aS6PiqYpQeqrVlRKvcEPnMAeoSleP3Da97y3sjsqK4ldmNVcgZSOBr7'
        b'0V1K6DY1hvhCXCDg/6oVct9IYm2rrHD0Cmve0iagFzQHhgjpvfw+j8D/a3AIHAXVqWh45ekpn3M8us0aNdwNHBdD/kWZvhqCh/8KvY2Z/ceBU'
        b'b9nGXHyD1ARoYlfpYJsC4bQ0mB07yjxfgXrBji30WuSq3OrPO1mhyNi4TU/aKprd+jxO4jVS2N+iR9z3e6nY4nlcatNQ+J7dcym7C2xKYGIHC'
        b'EkQShDoCeDxLRg9YGR0y5eGCiNMP5Rvstqs5m9S91xiN7Ukw9qR0VYf+b2JxYy3Cdd4kOuU+I31uJpUaCvgdQ4sdOZpeSkndN4aGvQj4nukyn'
        b'Nljs1RoCUXb3SXbjatnypGY9+ZCVlQ70s1AHR9fqGrZxd74YZ/GrFkfQRGpagFWM7ADYFoEmyv0HMemcXk/snRHYE5YjOwr4CE9T4oKczeRo5'
        b'6oKEV1vZIu3SdBeOgf45cWVkfjG7ThRmMqOXw7JIxI9PFh7EPpHx+/q3InK6iBs6hRR7jT9RoSTfyvCFm3ILzMnWGy+nDoKcnwRYAQbyG37Ut'
        b'0z3dkHN4jZ3xkpvpoezlOvU7gjjxDNqRwheG9u5/FToAiQ7IIfLgno8dteLSqIu150aa9xS8j6GMlP/3azDJ2cEv0wC2cvKp9zYKccpcWFPF7'
        b't6iiy9ENSioTaF3NrfTFmTD8MWmwVpcgBu3MGzCUeeDUrGAbeysKdjdvbw9XDpfUFLAGkVJdzOMveXgjw5aPKMfZDjrRQ2WMTABmwQQe+HeRo'
        b'KBcP5pEtZkiUowmZJwMwg6cmnwl45qtGQAxW0TL/NH8692sblA8NweWgdIPa8jQ5aTrwKBf9bdPgGC/f2wQWwhDbuLtboDtTLyRAiWMWTmhPH'
        b'uSgDhELYUM5ruwMyPTLKXEYhwxSAYUIQkzW6euyDTGo6+qgLXdiXy35VPCnzSq3BG/kkt4AVbzAcvjYdw0DlglppXtv9/BmldA2mlnxjdA10T'
        b'YY6iZQ9krE+BzRhzP84x3eCxkioecdTA01ZoIqsZL+9j2bgRqJwhCNrGqH9CRgzFUYsVNoNkFodRjyNmp0rAm6VIeesdy6PCM0MZLyYKaKYQ0'
        b'6Cda3f/ZP9kPEjcxucBPwabGFWyP9MxizyLN7Nj/hg2j2YCn9DgZLtJLpTGXMvfkXLwWAKRJ4Vt941j2MSClZcmqNc91AEGNrxH5N7VsPUUW7'
        b'MgNCW59ShdB6xoQyIHVL0upSi/kJnN3ec2YVcKHejBk5DjTk4o38D22Zb7iDDqbF1pKxvyfmM7tOk053i1YLehL14zMlVzGCSD2n8XTVxIPVL'
        b'UXggo38+4sLY8ViqZNoAC+RvnSJY1i/Tiupwub+/71nm2PCPmXgAcjmoNpq5/E7N6XrEv1BX9INCS2UijfeAYdk9XGxr3gKRVulhaZYPkB7ra'
        b'10VPonk/Y/zsGOEjncFehutWhYf57xh+5Q/rFBtLLRIRty3dDHvyLnPZ/1IoZ/NQMULHTEjGDsCZvsZ51WSQFUR1/yNJbczkVL+0XkGAl6oev'
        b'MDmkHQtcIrrqHf7jSmMTvcwf9WVTUG4+T2tin5ES7R2UvU+nMouJYQ2YVOny8YG8NyvwXIIFAW1mg7MzG8vlXXqUJI3xJii454V5UJoWA8pZn'
        b'osrocJMMc3S6QCDNpo5bAfAyLjK9p6A3V4dCuFmjo0BZ4lC8n6dt/ajUcyTb/uc2hPAY3SHVg3B2Vx/BQxN/sSGNxPQuSUKPytEREfM1gQIaG'
        b'DQp3844bwc2gxYLk8oviy2rAeraX7Ou10GQReuyeZyTenjHhv7OlBnPB8HJsUEC5NeE7HrJwe6n0ikUyaG8Bc+aEzspHiyLWwzwAG84ca81Gd'
        b'DYt8+M+COIRK39So55N26N4iWj2m6n1CPjnVc4QQq7rHqaLTCMwwSoVDnHrUZP4L+G2pOSNe565UgMmUoUE1JpjWjwmkys3mU65jP8d0Pe4ZJ'
        b'/Cz1y0VEh5y3hmRLYR3CDhzL1pnnURBnEJVl4IE+DuxpuvLmjZjXZo875ZALIpdUoUg7TLeLpiYRtQi1n80ur/UE8Q+4h+pjIRHgVsiJeMLsU'
        b'TrrglNWqg/32WqnLuMS4XWKo4Yc1fKP7W12HNjCsVftXLrXaudfvDJ97iigFQ9sw3KSdeJZqzQPJo6YPyU0PfMslzZ1WsukefZUWp7s7WqAgD'
        b'c26GuaqRU/qJqRhy+ICfItLA7tMb9ZVFVV/5wH4Sb3SfEdbVNosBqSEQdgXWQ91+Ki54x2+jvpue5NvRc9fD7Qyh2vzzDGXd3tqknjuXdmb6p'
        b'MzvOwtkxhHugH35x0zyboV2M3pgpre8DMv9oW/NYb11FT2LW1DLe4Awz+iiONkqiEa+qu0+8+100skJeWOT4tnp4eTNzgBeaqihZR2AhwZoUQ'
        b'fs1JgaNZZ7cymzEnpb6JON1GXfnE8IZbynUsYRCzyubZ8pr00oDD+LuZLrIKD1fPob84v69sfei+wv4dpJV671PiWrIwYc8D3Xpo4AD5iCUz9'
        b'UCNR4/tkp/GzsvYOpIFUcAPKUrkks8u3KYfoCfy3xVvggkRYp5A6rbObb+BjV7/7RplV7ZA9jj178cS9OLgsrPqPbpOTHWX2Bp+rhYKN7VSZ+'
        b'RzAIbQEX0PMl2j+0k/nYI7nO7LUzg6RwkiZb71fjWtATC9e6ch512YTKEtbNKshJJqSlDV9vxsGFzXJKDJLDxUk3EdNnObyI108PisuPF02YW'
        b'eqARfMFTNqlcWEKGPkm63/GefB5y/xDWEnGCZwB7TWyi5z75eMj0KC6xj1HavVD8DcC3f4wdgujDWHLsVUtSa/3ER2SYZOAJrPxDCrx0j3agZ'
        b'o/eDx7qU91RCLNRsASujF8iBejAfT4ic8CR1OmRmGYaGvIOX2KAZU343PG9Qo1rKeem5uLup0aArqLGz2Ue1C/wiOBbwBVZgHDxfnLFsypgcc'
        b'hE/JaCcviuRHLktCyKcmCxLmJrCidNUfXdB3c8Tpc/FE/7YxBFEFvkW8+s9WpiWAvFudPiBrnpL0j+Or1JIK3KKn1KJN2umLdrDGXpMHWCUkg'
        b'99REGQd89zUO74l8+G/aJliffP1z1Ogpww0HqcmlFBKM9EwNEt39lBKkquPdWoRkM7JRn/OdvXFvNEYf7OIzHrYYVQrE1Y6Yte21tHVqbrKs8'
        b'hM8AzxwvT9xcUaIYb0LUYlvMIPmmNHje9izczYU1DJvXjbgMvpAvdJShckJ4BU5ykLrNANgjw8zWII0K4VhnArq2m4W62/pkCFSf+ZeRnzTNI'
        b'JUgZy2QtGfKPHfj3V+FQUGU2ijNkahrdB5YaCCBrrRGdSuieKW85HO0qZXJtd8igHWVYtxJ8VrL+HHyCBPjD4WRCiSVCX6ND8VY6rFWu8PCLP'
        b'5CoYGQMnDHTSFKPvqiD7b7iIN6MXi/oJrCJVba/BHRVZluS9vVSt+g9A2LzVXOfdcNaAxZK8veej8iRM6x+m8o7D4Fqzk6wo+auAvr1zngiME'
        b'BTvO4BMXOtpMbNEZF65xY/xnxNZ6EW+DnJi8gSdeqLGYLn+OxSlRomxmDOncDEAICVL20xoCu6WmrsF7r0A/dV77ExMnAOho20RhazJOi8slS'
        b'1bfTAHhKqsgGmRGVyCgL+25HUXV0wg3Ul2fQJUMe2GgPP/8gjyGIUk4cFbXWOZB6pNFbt3FtDWFstcZ6aVMK75M1NPSQccqvbSVrrHM2jQGJx'
        b'd01opqTcVPLNH8lcgSX3BUp4+DTrtmD5puC2Z4HpjySTaw/0WA0CnoAGQxnS1gBZpHTMP7OcYlRcoWfTuEfSFfvPs1quY3OPgfGT23X4jKEI7'
        b'VwzHPQPOZ3IqvGIBXByT9N084MEaxmGy3GXtCAjXMwEnl+j9jesXBo1JK5ehxQOlVeU1Nl2dS80EPnHpgEuwBv6gU99FBxmQgkjpsFekY/i9s'
        b'rNMpnyrthS+/+UPCSC8bXxm5Sj7MXG0CK/GiwjxeJOmfl7lD9Y2PAA14v3OPMQYwA45H7a/4d2h7/zs+dMhZ/k7u2EIUlwDzCjvqR3pqYIhq6'
        b'mDI5Ycq8IWnuK1S4ppZnjxv5I11QU/pFdZtoHRJpA4y9Ngv/OOSfgwyaWfSjeB/WTo7v09Qo96txYZcCf9V80VUHLBdmcsKAhxan5T3TI/AUT'
        b'ecl0Q8dxXyYOjyHX0grdUzNnP7NBkLJThAYNXsLyxJskWSXgR7bjgq9e99L4VqHflVV8qQ6wsdmwW5OeRmV1DBwPvxy9/wA4eSJjIFEz08YEU'
        b'pO4qntFqkjveYKdiMZd/bc5HpPXH5mDS/Z2AT/FXxkMvj/d37ar8ZwT/8m8yUtc4pYtKtn4xSC2V3UKyJZPtpokaUZPGOIWwhrPIzuzTyykcH'
        b'qvcmMybUTtpsf8v5i45B/3/0Yxe1bdrPOu7CXw5nfdexfawr9aWm8+ufQ9woDEr4EaKT4pxX/XExjxrd7Nhv0XsGJ0gg+9dwcXvwWr72sOKxD'
        b'pqkdPduwTU+Ej2SS1piWZkQ80Q4/I973EYKASGgzrru4vDzdU25ATQIiLyAFXMaS6UbifLwcP4xO01RPyfiQGpIVLI5mH+ghaOR7vnpOqcgaq'
        b'xsLlpE02t0bTqUWaj3vYj/qJlk8Esixin8ZTNZGIGl6QaeIlAGxEreLzxbzy0p0HfYCW7XpfEAiLB3dAjNGWViP99/RSOA37N39tTrtSw9VTJ'
        b'IXsGy8dFkgIxy5i/U6q4MKXV4T8ju7LIhnXztG/0Ld4VwB4UbNJ1/fISAABxB+AMQAAsLFsY7HEZ/sCAAAAAARZWg=='
    ]

    def setUp(self) -> None:
        super().setUp()

        # self.backup_util = BackupUtil(self.contexte)

        # self.enveloppe_certificat = self.contexte.validateur_pki.valider(self.contexte.configuration.cle.chaine)
        # idmg = self.enveloppe_certificat.subject_organization_name
        # self.formatteur = FormatteurMessageMilleGrilles(idmg, self.contexte.signateur_transactions)

        self.files_for_cleanup = list()

        # self._requests_calls = list()
        # self._requests_response = RequestsReponse()

    def tearDown(self) -> None:
        super().tearDown()

        for f in self.files_for_cleanup:
            try:
                os.unlink(f)
            except FileNotFoundError:
                pass # OK
            except Exception:
                self.logger.exception("Erreur nettoyage fichier")

    def preparer_sampletar(self, idx: int):
        """
        Simule un download de backups horaire/snapshot a partir du serveur consignationfichiers
        :param idx:
        :return:
        """
        tmpfile = tempfile.mktemp(dir=UT_TEMP_FOLDER)

        with tarfile.open(tmpfile, 'w') as fichier_tar:
            nomfichier_catalogue = ArchivesBackupParserTest.SAMPLE_CATALOGUES_NOMS[idx]
            catalogue = b64decode(ArchivesBackupParserTest.SAMPLE_CATALOGUES[idx])
            path_fichier_catalogue = os.path.join(UT_TEMP_FOLDER, nomfichier_catalogue)
            with open(path_fichier_catalogue, 'wb') as fichier:
                fichier.write(catalogue)
            fichier_tar.add(path_fichier_catalogue, arcname=nomfichier_catalogue)
            os.unlink(os.path.join(UT_TEMP_FOLDER, path_fichier_catalogue))

            nomfichier_transactions = ArchivesBackupParserTest.SAMPLE_TRANSACTIONS_NOMS[idx]
            transactions = b64decode(ArchivesBackupParserTest.SAMPLE_TRANSACTIONS[idx])
            path_fichier_transactions = os.path.join(UT_TEMP_FOLDER, nomfichier_transactions)
            with open(path_fichier_transactions, 'wb') as fichier:
                fichier.write(transactions)
            fichier_tar.add(path_fichier_transactions, arcname=nomfichier_transactions)
            os.unlink(path_fichier_transactions)

        self.files_for_cleanup.append(tmpfile)
        return tmpfile

    def test_detecter_type_archive(self):
        archives_parser = ArchivesBackupParser(self.contexte)

        nom_fichier = 'grosfichiers/CID.xz'
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('grosfichier', type_archive)

        nom_fichier = ArchivesBackupParserTest.SAMPLE_TRANSACTIONS_NOMS[0]
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('transactions', type_archive)

        nom_fichier = ArchivesBackupParserTest.SAMPLE_CATALOGUES_NOMS[0]
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('catalogue', type_archive)

        nom_fichier = 'domaine_20200101-SNAPSHOT_dequoi.jsonl.xz'
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('snapshot_transactions', type_archive)

        nom_fichier = 'domaine_20200101-SNAPSHOT_dequoi.json.xz'
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('snapshot_catalogue', type_archive)

        nom_fichier = 'domaine_20200101_dequoi.tar'
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('tar', type_archive)

        nom_fichier = 'domaine_sousdomaine_20200101_dequoi.tar'
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('tar', type_archive)

        nom_fichier = 'domaine_20200101_dequoi.tar'
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('tar', type_archive)

        nom_fichier = 'domaine_sousdomaine_20200101_dequoi.tar'
        type_archive = archives_parser.detecter_type_archive(nom_fichier)
        self.assertEqual('tar', type_archive)

        nom_fichier = 'pasbon'
        self.assertRaises(TypeArchiveInconnue, archives_parser.detecter_type_archive, nom_fichier)

        nom_fichier = 'pas_bon'
        self.assertRaises(TypeArchiveInconnue, archives_parser.detecter_type_archive, nom_fichier)

        nom_fichier = 'tres_pas_bon'
        self.assertRaises(TypeArchiveInconnue, archives_parser.detecter_type_archive, nom_fichier)

        nom_fichier = 'super_tres_pas_bon'
        self.assertRaises(TypeArchiveInconnue, archives_parser.detecter_type_archive, nom_fichier)

        nom_fichier = 'quosse_ca_tres_pas_bon'
        self.assertRaises(TypeArchiveInconnue, archives_parser.detecter_type_archive, nom_fichier)

    def test_process_archive_horaire_catalogue(self):
        archives_parser = ArchivesBackupParser(self.contexte)

        # Generer fichier tar avec transaction/catalogue dummy et preparer lecture
        tmpfile = self.preparer_sampletar(0)
        with tarfile.open(tmpfile, mode='r', debug=3, errorlevel=3) as tar_stream:
            fichier_tar = tar_stream.next()
            tar_fo = tar_stream.extractfile(fichier_tar)

            # Caller methode a tester
            archives_parser._process_archive_horaire_catalogue(fichier_tar.name, tar_fo)

        # Verifications
        generateur_transactions = self.contexte.generateur_transactions
        message_catalogue = generateur_transactions.liste_emettre_message[0]['args'][0]
        message_domaine = generateur_transactions.liste_emettre_message[0]['args'][1]

        self.assertEqual('commande.transaction.restaurerTransaction', message_domaine)
        self.assertIsNotNone(message_catalogue)

    def test_process_archive_horaire_transaction(self):
        archives_parser = ArchivesBackupParser(self.contexte)

        # Generer fichier tar avec transaction/catalogue dummy et preparer lecture
        tmpfile = self.preparer_sampletar(0)
        with tarfile.open(tmpfile, mode='r', debug=3, errorlevel=3) as tar_stream:
            # Preparer catalogue
            fichier_tar = tar_stream.next()
            tar_fo = tar_stream.extractfile(fichier_tar)
            archives_parser._process_archive_horaire_catalogue(fichier_tar.name, tar_fo)

            # Tester transactions
            fichier_tar = tar_stream.next()
            tar_fo = tar_stream.extractfile(fichier_tar)

            # Caller methode a tester
            archives_parser._process_archive_horaire_transaction(fichier_tar.name, tar_fo)

        # Verifications
        generateur_transactions = self.contexte.generateur_transactions

        # Tester messages transactions, index=0 -> catalogue
        for i in range(1, 4):
            message_transactions = generateur_transactions.liste_emettre_message[i]['args'][0]
            message_domaine = generateur_transactions.liste_emettre_message[i]['args'][1]

            self.assertEqual('commande.transaction.restaurerTransaction', message_domaine)
            self.assertIsNotNone(message_transactions)
            self.assertEqual(message_transactions['valeur'], i)

    def test_process_archive_snapshot_catalogue(self):
        archives_parser = ArchivesBackupParser(self.contexte)

        # Generer fichier tar avec transaction/catalogue dummy et preparer lecture
        tmpfile = self.preparer_sampletar(0)
        with tarfile.open(tmpfile, mode='r', debug=3, errorlevel=3) as tar_stream:
            fichier_tar = tar_stream.next()
            tar_fo = tar_stream.extractfile(fichier_tar)

            # Caller methode a tester
            archives_parser._process_archive_snapshot_catalogue(fichier_tar.name, tar_fo)

        # Verifications
        generateur_transactions = self.contexte.generateur_transactions
        self.assertEqual(0, len(generateur_transactions.liste_emettre_message))

    def test_process_archive_snapshot_transaction(self):
        archives_parser = ArchivesBackupParser(self.contexte)

        # Generer fichier tar avec transaction/catalogue dummy et preparer lecture
        tmpfile = self.preparer_sampletar(0)
        with tarfile.open(tmpfile, mode='r', debug=3, errorlevel=3) as tar_stream:
            # Preparer catalogue
            fichier_tar = tar_stream.next()
            tar_fo = tar_stream.extractfile(fichier_tar)
            archives_parser._process_archive_snapshot_catalogue(fichier_tar.name, tar_fo)

            # Tester transactions
            fichier_tar = tar_stream.next()
            tar_fo = tar_stream.extractfile(fichier_tar)

            # Caller methode a tester
            archives_parser._process_archive_snapshot_transaction(fichier_tar.name, tar_fo)

        # Verifications
        generateur_transactions = self.contexte.generateur_transactions

        # Tester messages transactions, index=0 -> catalogue
        for i in range(0, 3):
            message_transactions = generateur_transactions.liste_emettre_message[i]['args'][0]
            message_domaine = generateur_transactions.liste_emettre_message[i]['args'][1]

            self.assertEqual('commande.transaction.restaurerTransaction', message_domaine)
            self.assertIsNotNone(message_transactions)
            self.assertEqual(message_transactions['valeur'], i+1)

    def test_demander_cle(self):
        archives_parser = ArchivesBackupParser(self.contexte)
        catalogue = {
            'domaine': 'test',
            'iv': 'IV_123',
            ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE: 'HACHAGE_DUMMY',
        }

        # Caller methode a tester
        reponse_cle = archives_parser.demander_cle(catalogue)

        generateur_transactions = self.contexte.generateur_transactions
        liste_transmettre_requete = generateur_transactions.liste_transmettre_requete
        requete = liste_transmettre_requete[0]['args'][0]
        domaine_action = liste_transmettre_requete[0]['args'][1]

        self.assertEqual('MaitreDesCles.dechiffrage', domaine_action)
        self.assertEqual('Backup', requete['domaine'])
        self.assertEqual('HACHAGE_DUMMY', requete['hachage_bytes'])

    def test_skip_demander_cle(self):
        archives_parser = ArchivesBackupParser(self.contexte)
        archives_parser.skip_chiffrage = True  # Flag pour ignorer transactions chiffres
        catalogue = {
            'domaine': 'test',
            'iv': 'IV_123',
            ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE: 'HACHAGE_DUMMY',
        }

        # Caller methode a tester
        reponse_cle = archives_parser.demander_cle(catalogue)

        generateur_transactions = self.contexte.generateur_transactions
        liste_transmettre_requete = generateur_transactions.liste_transmettre_requete
        self.assertEqual(0, len(liste_transmettre_requete))

    def test_process_archive_quotidienne(self):
        archives_parser = ArchivesBackupParser(self.contexte)

        # Generer fichier tar avec transaction/catalogue dummy et preparer lecture
        tarfile_1 = self.preparer_sampletar(0)

        with open(tarfile_1, 'rb') as tar_stream:
            # Caller methode a tester
            archives_parser._process_archive_aggregee(tar_stream)

        # Verifications
        generateur_transactions = self.contexte.generateur_transactions
        message_catalogue = generateur_transactions.liste_emettre_message[0]['args'][0]
        message_domaine = generateur_transactions.liste_emettre_message[0]['args'][1]

        self.assertEqual(4, len(generateur_transactions.liste_emettre_message))
        self.assertEqual('commande.transaction.restaurerTransaction', message_domaine)
        self.assertIsNotNone(message_catalogue)

    def test_process_archive_annuelle(self):
        archives_parser = ArchivesBackupParser(self.contexte)

        # Generer fichier tar avec transaction/catalogue dummy et preparer lecture
        tarfile_1 = self.preparer_sampletar(0)

        # Ajouter fichier TAR (equivalent d'archive quotidienne) dans une _super_ archive (annuelle)
        tmp_basetar = tempfile.mktemp(dir=UT_TEMP_FOLDER)
        self.files_for_cleanup.append(tmp_basetar)

        with tarfile.open(tmp_basetar, 'w') as fichier_tar:
            fichier_tar.add(tarfile_1, arcname='jour_1.tar')
            fichier_tar.add(tarfile_1, arcname='jour_2.tar')
            fichier_tar.add(tarfile_1, arcname='jour_3.tar')

        with open(tmp_basetar, 'rb') as tar_stream:
            # Caller methode a tester
            archives_parser._process_archive_aggregee(tar_stream)

        # Verifications
        generateur_transactions = self.contexte.generateur_transactions
        message_catalogue = generateur_transactions.liste_emettre_message[0]['args'][0]
        message_domaine = generateur_transactions.liste_emettre_message[0]['args'][1]

        self.assertEqual('commande.transaction.restaurerTransaction', message_domaine)
        self.assertIsNotNone(message_catalogue)
        self.assertEqual(12, len(generateur_transactions.liste_emettre_message))

    def test_override_callbacks(self):
        """
        Override de la methode de traitement de ficheirs de transactions
        :return:
        """
        archives_parser = ArchivesBackupParser(self.contexte)

        # Generer fichier tar avec transaction/catalogue dummy et preparer lecture
        tarfile_1 = self.preparer_sampletar(0)

        # Ajouter fichier TAR (equivalent d'archive quotidienne) dans une _super_ archive (annuelle)
        tmp_basetar = tempfile.mktemp(dir=UT_TEMP_FOLDER)
        self.files_for_cleanup.append(tmp_basetar)

        with tarfile.open(tmp_basetar, 'w') as fichier_tar:
            fichier_tar.add(tarfile_1, arcname='jour_1.tar')
            fichier_tar.add(tarfile_1, arcname='jour_2.tar')
            fichier_tar.add(tarfile_1, arcname='jour_3.tar')

        catalogues = list()

        def callback_catalogue(domaine: str, catalogue: dict):
            catalogues.append(catalogue)

        archives_parser.callback_catalogue = callback_catalogue

        transactions = list()

        # Override methode callback transactions
        def callback_transactions_override(domaine: str, catalogue: dict, transaction: dict):
            transactions.append(transaction)

        archives_parser.callback_transactions = callback_transactions_override

        with open(tmp_basetar, 'rb') as tar_stream:
            # Caller methode a tester
            archives_parser._process_archive_aggregee(tar_stream)

        # Verifications
        self.assertEqual(3, len(catalogues))
        self.assertEqual(9, len(transactions))

    def test_skip_transactions(self):
        """
        Override de la methode de traitement de ficheirs de transactions
        :return:
        """
        archives_parser = ArchivesBackupParser(self.contexte)
        archives_parser.skip_transactions = True

        # Generer fichier tar avec transaction/catalogue dummy et preparer lecture
        tarfile_1 = self.preparer_sampletar(0)

        # Ajouter fichier TAR (equivalent d'archive quotidienne) dans une _super_ archive (annuelle)
        tmp_basetar = tempfile.mktemp(dir=UT_TEMP_FOLDER)
        self.files_for_cleanup.append(tmp_basetar)

        with tarfile.open(tmp_basetar, 'w') as fichier_tar:
            fichier_tar.add(tarfile_1, arcname='jour_1.tar')
            fichier_tar.add(tarfile_1, arcname='jour_2.tar')
            fichier_tar.add(tarfile_1, arcname='jour_3.tar')

        with open(tmp_basetar, 'rb') as tar_stream:
            # Caller methode a tester
            archives_parser._process_archive_aggregee(tar_stream)

        # Verifications
        generateur_transactions = self.contexte.generateur_transactions
        message_catalogue = generateur_transactions.liste_emettre_message[0]['args'][0]
        message_domaine = generateur_transactions.liste_emettre_message[0]['args'][1]

        self.assertEqual('commande.transaction.restaurerTransaction', message_domaine)
        self.assertIsNotNone(message_catalogue)
        self.assertEqual(3, len(generateur_transactions.liste_emettre_message))

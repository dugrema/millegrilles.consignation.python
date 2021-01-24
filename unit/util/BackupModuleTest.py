import datetime
import pytz
import json
import os
import lzma

from base64 import b64decode
from io import BytesIO, StringIO
from lzma import LZMAFile, LZMAError
from typing import Optional

from unit.helpers.TestBaseContexte import TestCaseContexte
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup, ConstantesGrosFichiers
from millegrilles.util.BackupModule import BackupUtil, HandlerBackupDomaine, InformationSousDomaineHoraire
from millegrilles.transaction.FormatteurMessage import FormatteurMessageMilleGrilles
from millegrilles.domaines.GrosFichiers import HandlerBackupGrosFichiers
from millegrilles.domaines.MaitreDesCles import HandlerBackupMaitreDesCles


class RequestsReponse:

    def __init__(self):
        self.status_code = 200
        self.json = {
            'fichiersDomaines': {
                'backup.jsonl': 'allo'
            }
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
        cipher, transaction_maitrecles = self.backup_util.preparer_cipher(dict(), info_cles)

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
        self.assertEqual(32, len(resultat), "Erreur taille resultat cipher")

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
        self.handler_protege.transmettre_evenement_backup('evenement_test', ts)

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
        self.assertEqual('/tmp/mgbackup/sousdomaine_test_transactions_2021011821_1.public.jsonl.xz', information_sousgroupe.path_fichier_backup)
        self.assertEqual('/tmp/mgbackup/sousdomaine_test_catalogue_2021011821_1.public.json.xz', information_sousgroupe.path_fichier_catalogue)

        catalogue_backup = information_sousgroupe.catalogue_backup
        self.assertEqual('sousdomaine_test', catalogue_backup['domaine'])
        self.assertEqual(Constantes.SECURITE_PUBLIC, catalogue_backup['securite'])
        self.assertEqual(ts_groupe, catalogue_backup['heure'])
        self.assertEqual('sousdomaine_test_catalogue_2021011821_1.public.json.xz', catalogue_backup['catalogue_nomfichier'])
        self.assertEqual('sousdomaine_test_transactions_2021011821_1.public.jsonl.xz', catalogue_backup['transactions_nomfichier'])
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
        self.assertEqual('/tmp/mgbackup/sousdomaine_test_transactions_202101182100-SNAPSHOT_1.public.jsonl.xz', information_sousgroupe.path_fichier_backup)
        self.assertEqual('/tmp/mgbackup/sousdomaine_test_catalogue_202101182100-SNAPSHOT_1.public.json.xz', information_sousgroupe.path_fichier_catalogue)

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
        cipher, transaction_maitrecles = self.backup_util.preparer_cipher(dict(), info_cles)
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
        self.handler_protege.transmettre_trigger_jour_precedent(ts)

        # Verification
        generateur_transactions = self.contexte.generateur_transactions
        evenement, domaine_action = generateur_transactions.liste_transmettre_commande[0]['args']
        self.assertEqual('commande.TestDomaine.declencherBackupQuotidien', domaine_action)
        self.assertEqual('TestDomaine', evenement['domaine'])
        self.assertLess(evenement['jour'], (ts-datetime.timedelta(days=1)).timestamp())
        self.assertGreater(evenement['jour'], (ts-datetime.timedelta(days=2)).timestamp())

    def test_transmettre_trigger_annee_precedente(self):
        ts = datetime.datetime(2021, 1, 18, 21, 0)
        self.handler_protege.transmettre_trigger_annee_precedente(ts)

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
        self.assertEqual('3.protege', catalogue['securite'])
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
        self.assertDictEqual(data, {'timestamp_backup': 1611003600, 'transaction_maitredescles': 'null'})
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
            'securite': '3.protege',
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
        self.handler_protege.creer_backup_quoditien('sousdomaine_test', ts)

        # Verifications
        calls_find = document_dao.calls_find
        info_commande_quotidien = self.contexte.generateur_transactions.liste_transmettre_commande[0]
        info_commande_annuel = self.contexte.generateur_transactions.liste_transmettre_commande[1]

        self.assertDictEqual(info_commande_annuel['args'][0], {'annee': 1546300800, 'domaine': 'TestDomaine', 'securite': '2.prive'})
        self.assertEqual('commande.TestDomaine.declencherBackupAnnuel', info_commande_annuel['args'][1])
        self.assertDictEqual(info_commande_quotidien['args'][0], {'catalogue': {'jour': 1610845200, 'en-tete': {'uuid_transaction': 'dummy.0'}}})
        self.assertEqual('commande.backup.genererBackupQuotidien', info_commande_quotidien['args'][1])

    def test_creer_backup_annuel(self):
        ts = datetime.datetime(2020, 8, 18, 21, 0)

        document_dao = self.contexte.document_dao
        document_dao.valeurs_find.append([{
            'annee': datetime.datetime(2020, 1, 17, 0, 0)
        }])

        # Caller methode a tester
        self.handler_protege.creer_backup_annuel('sousdomaine_test', ts)

        # Verifications
        calls_find = document_dao.calls_find
        info_commande_annuel = self.contexte.generateur_transactions.liste_transmettre_commande[0]

        self.assertDictEqual(info_commande_annuel['args'][0], {'catalogue': {'annee': 1579219200, 'en-tete': {'uuid_transaction': 'dummy.0'}}})
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
        self.assertEqual('/tmp/ut_backupmoduletest/sousdomaine_test_transactions_2021011821_3.protege.jsonl.xz', information_sousgroupe.path_fichier_backup)
        self.assertEqual('/tmp/ut_backupmoduletest/sousdomaine_test_catalogue_2021011821_3.protege.json.xz', information_sousgroupe.path_fichier_catalogue)


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
        document_dao.valeurs_aggregate.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup
        document_dao.valeurs_find.append([
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
            self.formatteur.signer_message({'valeur': 3})[0],
        ])

        self._requests_response.json = {
            'fichiersDomaines': dict()
        }

        # Caller methode a tester
        self.handler_public.backup_horaire_domaine(ts, info_cles)

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
                    if f.find('catalogue') > 0:
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
        document_dao.valeurs_aggregate.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup, 3 groupes pour test de chainage
        document_dao.valeurs_find.append([self.formatteur.signer_message({'valeur': 1})[0]])
        document_dao.valeurs_find.append([self.formatteur.signer_message({'valeur': 2})[0]])
        document_dao.valeurs_find.append([self.formatteur.signer_message({'valeur': 3})[0]])

        self._requests_response.json = {
            'fichiersDomaines': dict()
        }

        # Caller methode a tester
        self.handler_public.backup_horaire_domaine(ts, info_cles)

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
                    if f.find('catalogue') > 0:
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
        document_dao.valeurs_aggregate.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup
        document_dao.valeurs_find.append([
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
            self.formatteur.signer_message({'valeur': 3})[0],
        ])

        self._requests_response.json = {
            'fichiersDomaines': dict()
        }

        # Caller methode a tester
        self.handler_protege.backup_horaire_domaine(ts, info_cles)

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
                if f.find('transaction') > 0:
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
        document_dao.valeurs_aggregate.append(None)  # Plus recent backup (pour entete)

        # Preparer transactions pour le backup
        document_dao.valeurs_find.append([
            self.formatteur.signer_message({'valeur': 1})[0],
            self.formatteur.signer_message({'valeur': 2})[0],
            self.formatteur.signer_message({'valeur': 3})[0],
        ])

        self._requests_response.json = {
            'fichiersDomaines': dict()
        }

        # Caller methode a tester
        self.handler_public.backup_horaire_domaine(ts, info_cles, snapshot=True)

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
                    if f.find('catalogue') > 0:
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

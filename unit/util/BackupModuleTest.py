import datetime
import pytz

from base64 import b64decode

from unit.helpers.TestBaseContexte import TestCaseContexte
from millegrilles import Constantes
from millegrilles.util.BackupModule import BackupUtil, HandlerBackupDomaine, InformationSousDomaineHoraire


class BackupUtilTest(TestCaseContexte):

    def setUp(self) -> None:
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
        self.handler_protege = HandlerBackupDomaine(
            self.contexte, "TestDomaine", "TestTransactions", "TestDocuments",
            niveau_securite=Constantes.SECURITE_PROTEGE
        )
        self.handler_public = HandlerBackupDomaine(
            self.contexte, "TestDomaine", "TestTransactions", "TestDocuments",
            niveau_securite=Constantes.SECURITE_PUBLIC
        )

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
        groupe = resultat[0]
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
        self.assertEqual(2, len(catalogue_backup['certificats_pem']))

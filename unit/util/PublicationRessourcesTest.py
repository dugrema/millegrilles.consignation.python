import json
import logging
import multibase

from unit.helpers.TestBaseContexte import TestCaseContexte
from io import BytesIO

from millegrilles import Constantes
from millegrilles.util.PublicationRessources import InvalidateurRessources, TriggersPublication, HttpPublication, RessourcesPublication
from millegrilles.Constantes import ConstantesPublication, ConstantesGrosFichiers, ConstantesMaitreDesCles


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

    def raise_for_status(self):
        pass


class StubCascade:

    def __init__(self, contexte):
        self.__contexte = contexte
        self.demarrer_processus_calls = list()
        self.marquer_ressource_complete_calls = list()
        self.marquer_ressource_encours_calls = list()
        self.transmettre_commande_calls = list()
        self.sauvegarder_contenu_gzip_calls = list()
        self.preparer_siteconfig_publication_calls = list()
        self.maj_ressource_mapping_calls = list()
        self.maj_ressources_page_calls = list()
        self.trouver_ressources_manquantes_calls = list()
        self.continuer_publication_calls = list()
        self.preparer_enveloppe_calls = list()
        self.invalider_ressources_sections_fichiers_calls = list()

        self.site = {'site_id': 'DUMMY-site'}

        self.ressource_page_retour = None

    def get_site(self, site_id):
        return self.site

    @property
    def document_dao(self):
        return self.__contexte.document_dao

    def demarrer_processus(self, *args, **kwargs):
        self.demarrer_processus_calls.append({'args': args, 'kwargs': kwargs})

    def preparer_permission_secret(self, *args, **kwargs):
        return 'PERMISSION DUMMY'

    # MOCK trigger
    def marquer_ressource_complete(self, *args, **kwargs):
        self.marquer_ressource_complete_calls.append({'args': args, 'kwargs': kwargs})

    def marquer_ressource_encours(self, *args, **kwargs):
        self.marquer_ressource_encours_calls.append({'args': args, 'kwargs': kwargs})

    def invalider_ressources_sections_fichiers(self, *args, **kwargs):
        self.invalider_ressources_sections_fichiers_calls.append({'args': args, 'kwargs': kwargs})

    # MOCK generateur transactions
    def transmettre_commande(self, *args, **kwargs):
        self.transmettre_commande_calls.append({'args': args, 'kwargs': kwargs})

    # MOCK ressources
    def sauvegarder_contenu_gzip(self, *args, **kwargs):
        self.sauvegarder_contenu_gzip_calls.append({'args': args, 'kwargs': kwargs})

    def preparer_siteconfig_publication(self, *args, **kwargs):
        self.preparer_siteconfig_publication_calls.append({'args': args, 'kwargs': kwargs})

    def maj_ressource_mapping(self, *args, **kwargs):
        self.maj_ressource_mapping_calls.append({'args': args, 'kwargs': kwargs})

    def maj_ressources_page(self, *args, **kwargs):
        self.maj_ressources_page_calls.append({'args': args, 'kwargs': kwargs})
        return self.ressource_page_retour

    def trouver_ressources_manquantes(self, *args, **kwargs):
        self.trouver_ressources_manquantes_calls.append({'args': args, 'kwargs': kwargs})

    def continuer_publication(self, *args, **kwargs):
        self.continuer_publication_calls.append({'args': args, 'kwargs': kwargs})

    def preparer_enveloppe(self, *args, **kwargs):
        self.preparer_enveloppe_calls.append({'args': args, 'kwargs': kwargs})
        return args[0]

    @property
    def invalidateur(self):
        # Agit comme mock
        return self

    @property
    def generateur_transactions(self):
        # Agit comme mock
        return self

    @property
    def ressources(self):
        # Agit comme mock
        return self


class HttpPublicationStub(HttpPublication):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls_requests_put = list()

    def requests_put(self, *args, **kwargs):
        self.calls_requests_put.append({
            'args': args,
            'kwargs': kwargs,
        })
        return RequestsReponse()


class InvalidateurRessourcesTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()
        self.cascade = StubCascade(self.contexte)
        self.invalidateur = InvalidateurRessources(self.cascade)

    def test_marquer_ressource_encours(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        cdn_id = 'abcd-1234'
        filtre_ressources = {'filtre': 'DUMMY'}

        # Executer code
        self.invalidateur.marquer_ressource_encours(cdn_id, filtre_ressources)

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        self.assertIsNotNone(update_calls[0])
        self.assertEqual(True, update_calls[0]['args'][1]['$set']['distribution_progres.abcd-1234'])
        self.assertEqual(True, update_calls[0]['args'][1]['$currentDate']['distribution_maj'])
        self.assertEqual(False, update_calls[0]['kwargs']['upsert'])

    def test_marquer_ressource_complete(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        cdn_id = 'abcd-1234'
        filtre_ressources = {'filtre': 'DUMMY'}

        # Executer code
        self.invalidateur.marquer_ressource_complete(cdn_id, filtre_ressources)

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        self.assertIsNotNone(update_calls[0])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_progres.abcd-1234'])
        self.assertEqual('abcd-1234', update_calls[0]['args'][1]['$addToSet']['distribution_complete'])
        self.assertEqual(True, update_calls[0]['args'][1]['$currentDate']['distribution_maj'])
        self.assertEqual(0, len(update_calls[0]['kwargs']))

    def test_invalider_ressource_mapping(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        # Executer code
        self.invalidateur.invalider_ressource_mapping()

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        self.assertIsNotNone(update_calls[0])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_complete'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_erreur'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_maj'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['date_signature'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['contenu'])
        self.assertEqual(0, len(update_calls[0]['kwargs']))

    def test_invalider_ressources_pages(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        section_ids = ['abcd-1234', 'abcd-1235']

        # Executer code
        self.invalidateur.invalider_ressources_pages(section_ids)

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        self.assertIsNotNone(update_calls[0])
        self.assertListEqual(section_ids, update_calls[0]['args'][0]['section_id']['$in'])
        self.assertEqual('page', update_calls[0]['args'][0]['_mg-libelle'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_complete'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_erreur'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_maj'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['date_signature'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['contenu'])
        self.assertEqual(0, len(update_calls[0]['kwargs']))

    def test_invalider_ressources_sections_fichiers(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        section_ids = ['abcd-1234', 'abcd-1235']

        # Executer code
        self.invalidateur.invalider_ressources_sections_fichiers(section_ids)

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        self.assertIsNotNone(update_calls[0])
        self.assertListEqual(section_ids, update_calls[0]['args'][0]['uuid']['$in'])
        self.assertEqual('collection_fichiers', update_calls[0]['args'][0]['_mg-libelle'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_complete'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_erreur'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_maj'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['date_signature'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['contenu'])
        self.assertEqual(0, len(update_calls[0]['kwargs']))

    def test_invalider_ressources(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        filtre = {'filtre': 'DUMMY'}

        # Executer code
        self.invalidateur.invalider_ressources(filtre)

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        self.assertIsNotNone(update_calls[0])
        self.assertDictEqual(filtre, update_calls[0]['args'][0])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_complete'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_erreur'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['distribution_maj'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['date_signature'])
        self.assertEqual(True, update_calls[0]['args'][1]['$unset']['contenu'])
        self.assertEqual(0, len(update_calls[0]['kwargs']))

    def test_marquer_collection_fichiers_prete(self):
        # Preparer donnees update
        self.contexte.document_dao.calls_find_update.append({'ok': True})
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        uuid_collection = 'abcd-1234'

        # Executer code
        self.invalidateur.marquer_collection_fichiers_prete(uuid_collection)

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_find_update
        self.assertIsNotNone(update_calls[0])

        self.assertEqual('collection_fichiers', update_calls[1]['args'][0]['_mg-libelle'])
        self.assertEqual('abcd-1234', update_calls[1]['args'][0]['uuid'])
        self.assertEqual(True, update_calls[1]['args'][1]['$set']['preparation_ressources'])
        self.assertEqual(True, update_calls[1]['kwargs']['upsert'])


class TriggersPublicationTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()
        self.cascade = StubCascade(self.contexte)
        self.trigger = TriggersPublication(self.cascade)

        self.site = {
            ConstantesPublication.CHAMP_SITE_ID: 'site-DUMMY',
            ConstantesPublication.CHAMP_LISTE_CDNS: ['CDN-1'],
        }

        self.cdn = {
            ConstantesPublication.CHAMP_CDN_ID: 'CDN-1',
            ConstantesPublication.CHAMP_TYPE_CDN: 'CDN DUMMY',
        }

    def test_preparer_sitesparcdn(self):
        # Preparer donnees update
        # Sites
        self.contexte.document_dao.valeurs_find.append([
            self.site,
        ])

        # CDNS
        self.contexte.document_dao.valeurs_find.append([
            self.cdn,
        ])

        # Executer code
        cdns = self.trigger.preparer_sitesparcdn()

        self.assertEqual(1, len(cdns))
        self.assertEqual('site-DUMMY', cdns[0]['sites'][0])

    def test_demarrer_publication_complete(self):
        params = {
        }

        self.contexte.document_dao.valeurs_find.append([self.site])
        self.contexte.document_dao.valeurs_find.append([self.cdn])
        self.contexte.document_dao.valeurs_update.append([self.cdn])
        self.contexte.document_dao.update_result.matched_count_value = 1

        compteur = self.trigger.demarrer_publication_complete(params)

        self.assertEqual(1, compteur)

        continuer_publication_calls = self.cascade.continuer_publication_calls
        trouver_ressources_manquantes_calls = self.cascade.trouver_ressources_manquantes_calls
        calls_find = self.cascade.document_dao.calls_find
        calls_update = self.cascade.document_dao.calls_update
        valeurs_update = self.cascade.document_dao.valeurs_update

        self.assertEqual(2, len(calls_find))
        self.assertEqual(1, len(calls_update))
        self.assertEqual(1, len(trouver_ressources_manquantes_calls))
        self.assertEqual(1, len(valeurs_update))
        self.assertEqual(1, len(continuer_publication_calls))

    def test_demarrer_publication_complete_nopublish(self):
        params = {
            'nopublish': True,
        }

        self.contexte.document_dao.valeurs_find.append([self.site])
        self.contexte.document_dao.valeurs_find.append([self.cdn])
        self.contexte.document_dao.valeurs_update.append([self.cdn])
        self.contexte.document_dao.update_result.matched_count_value = 1

        compteur = self.trigger.demarrer_publication_complete(params)

        self.assertEqual(1, compteur)

        continuer_publication_calls = self.cascade.continuer_publication_calls
        trouver_ressources_manquantes_calls = self.cascade.trouver_ressources_manquantes_calls
        calls_find = self.cascade.document_dao.calls_find
        calls_update = self.cascade.document_dao.calls_update
        valeurs_update = self.cascade.document_dao.valeurs_update

        self.assertEqual(2, len(calls_find))
        self.assertEqual(1, len(calls_update))
        self.assertEqual(1, len(trouver_ressources_manquantes_calls))
        self.assertEqual(1, len(valeurs_update))
        self.assertEqual(0, len(continuer_publication_calls))

    def test_demarrer_publication_complete_nomatch(self):
        params = {
        }

        self.contexte.document_dao.valeurs_find.append([self.site])
        self.contexte.document_dao.valeurs_find.append([self.cdn])
        self.contexte.document_dao.valeurs_update.append([self.cdn])
        self.contexte.document_dao.update_result.matched_count_value = 0

        compteur = self.trigger.demarrer_publication_complete(params)

        self.assertEqual(0, compteur)

        continuer_publication_calls = self.cascade.continuer_publication_calls
        trouver_ressources_manquantes_calls = self.cascade.trouver_ressources_manquantes_calls
        calls_find = self.cascade.document_dao.calls_find
        calls_update = self.cascade.document_dao.calls_update
        valeurs_update = self.cascade.document_dao.valeurs_update

        self.assertEqual(2, len(calls_find))
        self.assertEqual(1, len(calls_update))
        self.assertEqual(1, len(trouver_ressources_manquantes_calls))
        self.assertEqual(1, len(valeurs_update))
        self.assertEqual(1, len(continuer_publication_calls))

    def test_trigger_traitement_collections_fichiers_prep_true(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_find.append([
            {ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True},
        ])
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        # Executer code
        self.trigger.trigger_traitement_collections_fichiers()

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        self.assertEqual(0, len(update_calls))

    def test_trigger_traitement_collections_fichiers_pre_encours(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_find.append([
            {ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: 'en_cours'},
        ])

        # Executer code
        self.trigger.trigger_traitement_collections_fichiers()

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        self.assertEqual(0, len(update_calls))

    def test_trigger_traitement_collections_fichiers_prep_false(self):
        # Preparer donnees update
        self.contexte.document_dao.valeurs_find.append([
            {
                ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: 'abcd-1234',
                ConstantesPublication.CHAMP_LISTE_SITES: ['site-1'],
            },
        ])
        self.contexte.document_dao.valeurs_update.append({'ok': True})

        # Executer code
        self.trigger.trigger_traitement_collections_fichiers()

        # Verifier resultats
        update_calls = self.contexte.document_dao.calls_update
        demarrer_processus_calls = self.cascade.demarrer_processus_calls

        self.assertEqual(1, len(update_calls))
        self.assertEqual(1, len(demarrer_processus_calls))

        self.assertEqual('abcd-1234', update_calls[0]['args'][0]['uuid'])
        self.assertEqual('collection_fichiers', update_calls[0]['args'][0]['_mg-libelle'])
        self.assertEqual('en_cours', update_calls[0]['args'][1]['$set']['preparation_ressources'])

    def test_trigger_publication_fichiers_cdndummy(self):
        res_fichier = {
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'CDN-1': False},
            'fuuid': 'DUMMY-fuuid'
        }

        self.contexte.document_dao.valeurs_find.append([self.site])
        self.contexte.document_dao.valeurs_find.append([self.cdn])
        self.contexte.document_dao.valeurs_find.append([res_fichier])

        # self.trigger.trigger_publication_fichiers()
        self.assertRaises(Exception, self.trigger.trigger_publication_fichiers)

    def test_trigger_publication_fichiers_cdn_sftp(self):
        res_fichier = {
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'CDN-1': False},
            'fuuid': 'DUMMY-fuuid'
        }
        self.cdn[ConstantesPublication.CHAMP_TYPE_CDN] = 'sftp'
        self.cdn['host'] = 'DUMMY-host'
        self.cdn['port'] = 22
        self.cdn['username'] = 'DUMMY-username'
        self.cdn['repertoireRemote'] = 'DUMMY-remote/folder'

        self.contexte.document_dao.valeurs_find.append([self.site])
        self.contexte.document_dao.valeurs_find.append([self.cdn])
        self.contexte.document_dao.valeurs_find.append([res_fichier])

        compte_fichiers_publies = self.trigger.trigger_publication_fichiers()
        self.assertEqual(1, compte_fichiers_publies)

        marquer_ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        calls_find = self.cascade.document_dao.calls_find

        self.assertEqual(3, len(calls_find))
        self.assertEqual(1, len(marquer_ressource_encours_calls))
        self.assertEqual(1, len(transmettre_commande_calls))

    def test_trigger_publication_fichiers_cdn_ipfs(self):
        res_fichier = {
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'CDN-1': False},
            'fuuid': 'DUMMY-fuuid'
        }
        self.cdn[ConstantesPublication.CHAMP_TYPE_CDN] = 'ipfs'
        # self.cdn['repertoireRemote'] = 'DUMMY-remote/folder'

        self.contexte.document_dao.valeurs_find.append([self.site])
        self.contexte.document_dao.valeurs_find.append([self.cdn])
        self.contexte.document_dao.valeurs_find.append([res_fichier])

        compte_fichiers_publies = self.trigger.trigger_publication_fichiers()
        self.assertEqual(1, compte_fichiers_publies)

        marquer_ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        calls_find = self.cascade.document_dao.calls_find

        self.assertEqual(3, len(calls_find))
        self.assertEqual(1, len(marquer_ressource_encours_calls))
        self.assertEqual(1, len(transmettre_commande_calls))

    def test_trigger_publication_fichiers_cdn_awss3(self):
        res_fichier = {
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'CDN-1': False},
            'fuuid': 'DUMMY-fuuid'
        }
        self.cdn[ConstantesPublication.CHAMP_TYPE_CDN] = 'awss3'
        self.cdn['bucketName'] = 'DUMMY-bucketName'
        self.cdn['bucketDirfichier'] = 'DUMMY-remote/folder'
        self.cdn['bucketRegion'] = 'DUMMY-bucketRegion'
        self.cdn['credentialsAccessKeyId'] = 'DUMMY-credentialsAccessKeyId'
        self.cdn['secretAccessKey_chiffre'] = 'DUMMY-secretAccessKey_chiffre'

        self.contexte.document_dao.valeurs_find.append([self.site])
        self.contexte.document_dao.valeurs_find.append([self.cdn])
        self.contexte.document_dao.valeurs_find.append([res_fichier])

        compte_fichiers_publies = self.trigger.trigger_publication_fichiers()
        self.assertEqual(1, compte_fichiers_publies)

        marquer_ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        calls_find = self.cascade.document_dao.calls_find

        self.assertEqual(3, len(calls_find))
        self.assertEqual(1, len(marquer_ressource_encours_calls))
        self.assertEqual(1, len(transmettre_commande_calls))

        args_commande = transmettre_commande_calls[0]['args']
        self.assertEqual('commande.fichiers.publierFichierAwsS3', args_commande[1])
        self.assertEqual('2.prive', args_commande[0]['securite'])

    def test_trigger_publication_fichiers_cdn_hiddenService(self):
        res_fichier = {
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'CDN-1': False},
            'fuuid': 'DUMMY-fuuid'
        }
        self.cdn[ConstantesPublication.CHAMP_TYPE_CDN] = 'hiddenService'

        self.contexte.document_dao.valeurs_find.append([self.site])
        self.contexte.document_dao.valeurs_find.append([self.cdn])
        self.contexte.document_dao.valeurs_find.append([res_fichier])

        compte_fichiers_publies = self.trigger.trigger_publication_fichiers()
        self.assertEqual(0, compte_fichiers_publies)

        marquer_ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        calls_find = self.cascade.document_dao.calls_find

        self.assertEqual(2, len(calls_find))
        self.assertEqual(0, len(marquer_ressource_encours_calls))
        self.assertEqual(0, len(transmettre_commande_calls))

    def test_emettre_commande_publier_fichier_cdn_non_supporte(self):
        res_fichier = {'fuuid': 'FUUID-DUMMY'}
        self.assertRaises(Exception, self.trigger.emettre_commande_publier_fichier, res_fichier, self.cdn)

    def test_emettre_commande_publier_fichier(self):
        res_fichier = {'fuuid': 'FUUID-DUMMY'}
        self.cdn['type_cdn'] = 'mq'
        self.trigger.emettre_commande_publier_fichier(res_fichier, self.cdn)

        marquer_ressource_complete_calls = self.cascade.marquer_ressource_complete_calls
        self.assertEqual(1, len(marquer_ressource_complete_calls))

        marquer_ressource_args = marquer_ressource_complete_calls[0]['args']
        self.assertEqual('FUUID-DUMMY', marquer_ressource_args[1]['fuuid'])

    def test_emettre_commande_publier_fichier_sftp(self):
        res_fichier = {
            'fuuid': 'fuuid-DUMMY'
        }
        self.cdn['host'] = '1.2.3.4'
        self.cdn['port'] = 22
        self.cdn['username'] = 'DUMMY'
        self.cdn['repertoireRemote'] = '/rep/dummy'
        self.trigger.emettre_commande_publier_fichier_sftp(res_fichier, self.cdn)

        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        self.assertEqual(1, len(transmettre_commande_calls))
        transmettre_commande_args = transmettre_commande_calls[0]['args']
        self.assertEqual('commande.fichiers.publierFichierSftp', transmettre_commande_args[1])

    def test_emettre_commande_publier_fichier_ipfs(self):
        res_fichier = {
            'fuuid': 'fuuid-DUMMY'
        }
        self.cdn['host'] = '1.2.3.4'
        self.cdn['port'] = 22
        self.cdn['username'] = 'DUMMY'
        self.cdn['repertoireRemote'] = '/rep/dummy'
        self.trigger.emettre_commande_publier_fichier_ipfs(res_fichier, self.cdn)

        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        self.assertEqual(1, len(transmettre_commande_calls))
        transmettre_commande_args = transmettre_commande_calls[0]['args']
        self.assertEqual('commande.fichiers.publierFichierIpfs', transmettre_commande_args[1])

    def test_emettre_commande_publier_fichier_awss3(self):
        res_fichier = {
            'fuuid': 'fuuid-DUMMY'
        }
        self.cdn['bucketName'] = 'bucket DUMMY'
        self.cdn['bucketDirfichier'] = 'dir DUMMY'
        self.cdn['bucketRegion'] = 'region DUMMY'
        self.cdn['credentialsAccessKeyId'] = 'ID DUMMY'
        self.cdn['secretAccessKey_chiffre'] = multibase.encode('base64', b'ID DUMMY').decode('utf-8')
        self.cdn['repertoireRemote'] = '/rep/dummy'
        self.trigger.emettre_commande_publier_fichier_awss3(res_fichier, self.cdn)

        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        self.assertEqual(1, len(transmettre_commande_calls))
        transmettre_commande_args = transmettre_commande_calls[0]['args']
        self.assertEqual('commande.fichiers.publierFichierAwsS3', transmettre_commande_args[1])

    def test_emettre_publier_uploadpages_nochange(self):
        cdn_id = 'DUMMY-CDN'
        site_id = 'DUMMY-SITE'
        self.site['securite'] = Constantes.SECURITE_PUBLIC
        self.contexte.document_dao.valeurs_find.append(self.site)
        self.contexte.document_dao.valeurs_find.append([{
            ConstantesPublication.CHAMP_SECTION_ID: 'section-dummy',
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'DUMMY-CDN': True}
        }])

        compteur_commandes = self.trigger.emettre_publier_uploadpages(cdn_id, site_id)
        self.assertEqual(0, compteur_commandes)

    def test_emettre_publier_uploadpages_regenerer_progres_false(self):
        cdn_id = 'DUMMY-CDN'
        site_id = 'DUMMY-SITE'
        self.site['securite'] = Constantes.SECURITE_PUBLIC
        self.contexte.document_dao.valeurs_find.append(self.site)

        res_page = {
            ConstantesPublication.CHAMP_SECTION_ID: 'section-dummy',
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'DUMMY-CDN': False}
        }

        self.contexte.document_dao.valeurs_find.append([res_page])
        self.cascade.ressource_page_retour = res_page

        compteur_commandes = self.trigger.emettre_publier_uploadpages(cdn_id, site_id)
        self.assertEqual(1, compteur_commandes)

        maj_ressources_page_calls = self.cascade.maj_ressources_page_calls
        marquer_ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        sauvegarder_contenu_gzip_calls = self.cascade.sauvegarder_contenu_gzip_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        calls_find = self.cascade.document_dao.calls_find

        self.assertEqual(2, len(calls_find))
        self.assertEqual(1, len(maj_ressources_page_calls))
        self.assertEqual(1, len(marquer_ressource_encours_calls))
        self.assertEqual(1, len(sauvegarder_contenu_gzip_calls))
        self.assertEqual(1, len(transmettre_commande_calls))

    def test_emettre_publier_uploadpages_regenerer_progres_pas_false(self):
        cdn_id = 'DUMMY-CDN'
        site_id = 'DUMMY-SITE'
        self.site['securite'] = Constantes.SECURITE_PUBLIC
        self.contexte.document_dao.valeurs_find.append(self.site)

        res_page = {
            ConstantesPublication.CHAMP_SECTION_ID: 'section-dummy',
            # ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'DUMMY-CDN': True}
        }

        self.contexte.document_dao.valeurs_find.append([res_page])
        self.cascade.ressource_page_retour = res_page

        compteur_commandes = self.trigger.emettre_publier_uploadpages(cdn_id, site_id)
        self.assertEqual(0, compteur_commandes)

        maj_ressources_page_calls = self.cascade.maj_ressources_page_calls
        marquer_ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        sauvegarder_contenu_gzip_calls = self.cascade.sauvegarder_contenu_gzip_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        calls_find = self.cascade.document_dao.calls_find

        self.assertEqual(2, len(calls_find))
        self.assertEqual(0, len(maj_ressources_page_calls))
        self.assertEqual(0, len(marquer_ressource_encours_calls))
        self.assertEqual(0, len(sauvegarder_contenu_gzip_calls))
        self.assertEqual(0, len(transmettre_commande_calls))

    def test_emettre_publier_collectionfichiers(self):
        cdn_id = 'DUMMY-CDN'
        securite = Constantes.SECURITE_PUBLIC
        col_fichiers = {
            'uuid': 'DUMMY-uuid',
        }
        self.trigger.emettre_publier_collectionfichiers(cdn_id, col_fichiers, securite)

        contenu_gzip_calls = self.cascade.sauvegarder_contenu_gzip_calls
        ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls

        self.assertEqual(1, len(contenu_gzip_calls))
        self.assertEqual(2, len(ressource_encours_calls))
        self.assertEqual(1, len(transmettre_commande_calls))

        gzip_call_args1 = contenu_gzip_calls[0]['args']
        self.assertEqual('DUMMY-uuid', gzip_call_args1[0]['uuid'])

        ressource_args1 = ressource_encours_calls[0]['args']
        ressource_args2 = ressource_encours_calls[1]['args']

        self.assertEqual('DUMMY-CDN', ressource_args1[0])
        self.assertDictEqual({'_mg-libelle': 'collection_fichiers', 'uuid': 'DUMMY-uuid'}, ressource_args1[1])

        self.assertEqual('DUMMY-CDN', ressource_args2[0])
        self.assertDictEqual({'_mg-libelle': 'fichier', 'distribution_complete': {'$not': {'$all': ['DUMMY-CDN']}}, 'collections': {'$all': ['DUMMY-uuid']}}, ressource_args2[1])

        transmettre_commande_args1 = transmettre_commande_calls[0]['args']
        self.assertEqual('commande.Publication.publierUploadDataSection', transmettre_commande_args1[1])
        self.assertEqual({'type_section': 'collection_fichiers', 'uuid_collection': 'DUMMY-uuid', 'cdn_id': 'DUMMY-CDN', 'remote_path': 'data/fichiers/DUMMY-uuid.json.gz', 'mimetype': 'application/json', 'content_encoding': 'gzip', 'max_age': 0, 'securite': '1.public'}, transmettre_commande_args1[0])

    def test_emettre_publier_configuration_site_pas_encours(self):
        cdn_id = 'DUMMY-CDN'
        site_id = 'DUMMY-site'

        self.contexte.document_dao.valeurs_find.append([self.site])

        compte_commandes = self.trigger.emettre_publier_configuration(cdn_id, site_id)

        ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        siteconfig_calls = self.cascade.preparer_siteconfig_publication_calls

        resource_args1 = ressource_encours_calls[0]['args']
        transmettre_commande_args1 = transmettre_commande_calls[0]['args']

        self.assertEqual(1, compte_commandes)
        self.assertEqual('commande.Publication.publierUploadSiteConfiguration', transmettre_commande_args1[1])
        self.assertDictEqual({'site_id': 'site-DUMMY', 'cdn_id': 'DUMMY-CDN', 'remote_path': 'data/sites/site-DUMMY.json.gz', 'mimetype': 'application/json', 'content_encoding': 'gzip', 'max_age': 0}, transmettre_commande_args1[0])

        self.assertEqual(1, len(siteconfig_calls))
        self.assertDictEqual({'args': ('DUMMY-CDN', 'site-DUMMY'), 'kwargs': {}}, siteconfig_calls[0])

        self.assertEqual('DUMMY-CDN', resource_args1[0])
        self.assertDictEqual({'_mg-libelle': 'siteconfig', 'site_id': 'site-DUMMY'}, resource_args1[1])

    def test_emettre_publier_configuration_site_dist_encours(self):
        cdn_id = 'DUMMY-CDN'
        site_id = 'DUMMY-site'

        self.site[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES] = {'DUMMY-CDN': True}
        self.contexte.document_dao.valeurs_find.append([self.site])

        compte_commandes = self.trigger.emettre_publier_configuration(cdn_id, site_id)

        ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        siteconfig_calls = self.cascade.preparer_siteconfig_publication_calls

        self.assertEqual(0, compte_commandes)
        self.assertEqual(0, len(ressource_encours_calls))
        self.assertEqual(0, len(transmettre_commande_calls))
        self.assertEqual(0, len(siteconfig_calls))

    def test_emettre_publier_mapping_pas_encours(self):
        cdn_id = 'DUMMY-CDN'

        self.contexte.document_dao.valeurs_find.append([self.site])

        compte_commandes = self.trigger.emettre_publier_mapping(cdn_id)

        ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        mapping_calls = self.cascade.maj_ressource_mapping_calls

        resource_args1 = ressource_encours_calls[0]['args']
        transmettre_commande_args1 = transmettre_commande_calls[0]['args']

        self.assertEqual(1, compte_commandes)
        self.assertEqual(1, len(mapping_calls))

        self.assertEqual(cdn_id, resource_args1[0])
        self.assertDictEqual({'_mg-libelle': 'mapping'}, resource_args1[1])

        self.assertEqual('commande.Publication.publierUploadMapping', transmettre_commande_args1[1])
        self.assertDictEqual({'cdn_id': 'DUMMY-CDN', 'remote_path': 'index.json.gz', 'mimetype': 'application/json', 'content_encoding': 'gzip', 'max_age': 0}, transmettre_commande_args1[0])

    def test_emettre_publier_mapping_deja_encours(self):
        cdn_id = 'DUMMY-CDN'

        mapping = dict()
        mapping[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES] = {cdn_id: True}
        self.contexte.document_dao.valeurs_find.append(mapping)

        compte_commandes = self.trigger.emettre_publier_mapping(cdn_id)

        ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        mapping_calls = self.cascade.maj_ressource_mapping_calls

        self.assertEqual(1, compte_commandes)
        self.assertEqual(0, len(mapping_calls))
        self.assertEqual(0, len(ressource_encours_calls))
        self.assertEqual(0, len(transmettre_commande_calls))

    def test_emettre_publier_mapping_complete(self):
        cdn_id = 'DUMMY-CDN'

        mapping = dict()
        mapping[ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE] = [cdn_id]
        self.contexte.document_dao.valeurs_find.append(mapping)

        compte_commandes = self.trigger.emettre_publier_mapping(cdn_id)

        ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        mapping_calls = self.cascade.maj_ressource_mapping_calls

        self.assertEqual(0, compte_commandes)
        self.assertEqual(0, len(mapping_calls))
        self.assertEqual(0, len(ressource_encours_calls))
        self.assertEqual(0, len(transmettre_commande_calls))

    def test_emettre_publier_webapps_pas_encours_cdndummy(self):
        cdn_id = 'DUMMY-CDN'

        doc_webapp = {

        }
        res_webapp = {

        }

        self.contexte.document_dao.valeurs_find.append(doc_webapp)
        self.contexte.document_dao.valeurs_find.append(res_webapp)
        self.contexte.document_dao.valeurs_find.append(self.cdn)

        compte_commandes = self.trigger.emettre_publier_webapps(cdn_id)

        self.assertEqual(0, compte_commandes)

    def test_emettre_publier_webapps_pas_encours_cdn_ipfs_sanscle(self):
        cdn_id = 'DUMMY-CDN'

        self.cdn[ConstantesPublication.CHAMP_TYPE_CDN] = 'ipfs'
        doc_webapp = {

        }
        res_webapp = {

        }

        self.contexte.document_dao.valeurs_find.append(doc_webapp)
        self.contexte.document_dao.valeurs_find.append(res_webapp)
        self.contexte.document_dao.valeurs_find.append(self.cdn)

        compte_commandes = self.trigger.emettre_publier_webapps(cdn_id)

        processus_calls = self.cascade.demarrer_processus_calls

        self.assertEqual(1, compte_commandes)
        self.assertEqual(1, len(processus_calls))

        self.assertDictEqual({'cdn_id': 'CDN-1'}, processus_calls[0]['args'][1])
        self.assertEqual('millegrilles_domaines_Publication:ProcessusCreerCleIpnsVitrine', processus_calls[0]['args'][0])

    def test_emettre_publier_webapps_pas_encours_cdn_ipfs_aveccle(self):
        cdn_id = 'DUMMY-CDN'

        self.cdn[ConstantesPublication.CHAMP_TYPE_CDN] = 'ipfs'
        doc_webapp = {
            ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE: 'ma cle',
            ConstantesPublication.CHAMP_IPNS_ID: 'ma cle ID',
        }
        res_webapp = {

        }

        self.contexte.document_dao.valeurs_find.append(doc_webapp)
        self.contexte.document_dao.valeurs_find.append(res_webapp)
        self.contexte.document_dao.valeurs_find.append(self.cdn)

        compte_commandes = self.trigger.emettre_publier_webapps(cdn_id)

        processus_calls = self.cascade.demarrer_processus_calls
        commande_calls = self.cascade.transmettre_commande_calls

        self.assertEqual(1, compte_commandes)
        self.assertEqual(0, len(processus_calls))
        self.assertEqual(1, len(commande_calls))

        commande_args1 = commande_calls[0]['args']
        self.assertEqual('commande.fichiers.publierVitrineIpfs', commande_args1[1])
        self.assertDictEqual({'identificateur_document': {'_mg-libelle': 'webapps'}, 'ipns_key': 'ma cle', 'ipns_key_name': 'vitrine', 'permission': 'PERMISSION DUMMY', 'cdn_id': 'CDN-1', 'type_cdn': 'ipfs'}, commande_args1[0])

    def test_emettre_publier_webapps_pas_encours_cdn_sftp(self):
        cdn_id = 'DUMMY-CDN'

        self.cdn[ConstantesPublication.CHAMP_TYPE_CDN] = 'sftp'
        doc_webapp = dict()
        res_webapp = dict()

        self.contexte.document_dao.valeurs_find.append(doc_webapp)
        self.contexte.document_dao.valeurs_find.append(res_webapp)
        self.contexte.document_dao.valeurs_find.append(self.cdn)

        compte_commandes = self.trigger.emettre_publier_webapps(cdn_id)

        processus_calls = self.cascade.demarrer_processus_calls
        commande_calls = self.cascade.transmettre_commande_calls

        self.assertEqual(1, compte_commandes)
        self.assertEqual(0, len(processus_calls))
        self.assertEqual(1, len(commande_calls))

        commande_args1 = commande_calls[0]['args']
        self.assertEqual('commande.fichiers.publierVitrineSftp', commande_args1[1])
        self.assertDictEqual({'identificateur_document': {'_mg-libelle': 'webapps'}, 'cdn_id': 'CDN-1', 'type_cdn': 'sftp'}, commande_args1[0])

    def test_emettre_publier_webapps_pas_encours_cdn_awss3(self):
        cdn_id = 'DUMMY-CDN'

        self.cdn[ConstantesPublication.CHAMP_AWSS3_SECRETACCESSKEY_CHIFFRE] = 'mon secret chiffre'

        self.cdn[ConstantesPublication.CHAMP_TYPE_CDN] = 'awss3'
        doc_webapp = dict()
        res_webapp = dict()

        self.contexte.document_dao.valeurs_find.append(doc_webapp)
        self.contexte.document_dao.valeurs_find.append(res_webapp)
        self.contexte.document_dao.valeurs_find.append(self.cdn)

        compte_commandes = self.trigger.emettre_publier_webapps(cdn_id)

        processus_calls = self.cascade.demarrer_processus_calls
        commande_calls = self.cascade.transmettre_commande_calls

        self.assertEqual(1, compte_commandes)
        self.assertEqual(0, len(processus_calls))
        self.assertEqual(1, len(commande_calls))

        commande_args1 = commande_calls[0]['args']
        self.assertEqual('commande.fichiers.publierVitrineAwsS3', commande_args1[1])
        self.assertDictEqual({'identificateur_document': {'_mg-libelle': 'webapps'}, 'permission': 'PERMISSION DUMMY', 'cdn_id': 'CDN-1', 'type_cdn': 'awss3', 'secretAccessKey_chiffre': 'mon secret chiffre'}, commande_args1[0])

    def test_emettre_publier_webapps_encours(self):
        cdn_id = 'DUMMY-CDN'

        doc_webapp = {

        }
        res_webapp = {
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {cdn_id: True}
        }

        self.contexte.document_dao.valeurs_find.append(doc_webapp)
        self.contexte.document_dao.valeurs_find.append(res_webapp)
        self.contexte.document_dao.valeurs_find.append(self.cdn)

        compte_commandes = self.trigger.emettre_publier_webapps(cdn_id)

        processus_calls = self.cascade.demarrer_processus_calls
        commande_calls = self.cascade.transmettre_commande_calls

        self.assertEqual(1, compte_commandes)
        self.assertEqual(0, len(processus_calls))
        self.assertEqual(0, len(commande_calls))

    def test_emettre_publier_webapps_complete(self):
        cdn_id = 'DUMMY-CDN'

        doc_webapp = {

        }
        res_webapp = {
            ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: [cdn_id]
        }

        self.contexte.document_dao.valeurs_find.append(doc_webapp)
        self.contexte.document_dao.valeurs_find.append(res_webapp)
        self.contexte.document_dao.valeurs_find.append(self.cdn)

        compte_commandes = self.trigger.emettre_publier_webapps(cdn_id)

        processus_calls = self.cascade.demarrer_processus_calls
        commande_calls = self.cascade.transmettre_commande_calls

        self.assertEqual(0, compte_commandes)
        self.assertEqual(0, len(processus_calls))
        self.assertEqual(0, len(commande_calls))


class HttpPublicationTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()
        self.cascade = StubCascade(self.contexte)

        configuration = self.contexte.configuration
        self.http_publication = HttpPublicationStub(self.cascade, configuration)

        self.securite = Constantes.SECURITE_PUBLIC
        self.cdn = {
            ConstantesPublication.CHAMP_CDN_ID: 'CDN-1',
            ConstantesPublication.CHAMP_TYPE_CDN: 'CDN DUMMY',
        }

        self.res_data = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'DUMMY',
            ConstantesPublication.CHAMP_SECTION_ID: 'abcd-1234',
        }

    def test_put_publier_fichier_ipns_nokey(self):
        self.http_publication.put_publier_fichier_ipns(self.cdn, self.res_data, self.securite)

        # Verifier
        demarrer_processus_calls = self.cascade.demarrer_processus_calls

        self.assertEqual('millegrilles_domaines_Publication:ProcessusPublierCleEtFichierIpns', demarrer_processus_calls[0]['args'][0])
        process_arg1 = demarrer_processus_calls[0]['args'][1]
        self.assertDictEqual({'_mg-libelle': 'DUMMY', 'section_id': 'abcd-1234'}, process_arg1['identificateur_document'])
        self.assertEqual('abcd-1234', process_arg1['nom_cle'])
        self.assertEqual('1.public', process_arg1['securite'])
        self.assertEqual('CDN-1', process_arg1['cdn_id'])

    def test_put_publier_fichier_ipns_keyexist(self):
        self.res_data['ipns_id'] = 'ma_cle'
        self.res_data['ipns_cle_chiffree'] = multibase.encode('base64', b'abcd1234').decode('utf-8')
        self.res_data['contenu_gzip'] = b'mon contenu binaire DUMMY pas gzippe'

        self.http_publication.put_publier_fichier_ipns(self.cdn, self.res_data, self.securite)

        # Verifier
        calls_requests_put = self.http_publication.calls_requests_put
        self.assertEqual(1, len(calls_requests_put))
        request_put_args = calls_requests_put[0]['args']
        self.assertEqual('/publier/fichierIpns', request_put_args[0])

    def test_put_fichier_ipns(self):
        identificateur_document = {'doc': 'DUMMY'}
        ipns_key_name = 'cle IPNS DUMMY'
        self.res_data['ipns_cle_chiffree'] = multibase.encode('base64', b'abcd1234').decode('utf-8')
        self.res_data['contenu_gzip'] = b'mon contenu binaire DUMMY pas gzippe'

        self.http_publication.put_fichier_ipns(self.cdn, identificateur_document, ipns_key_name, self.res_data, self.securite)

        # Verifier
        calls_requests_put = self.http_publication.calls_requests_put
        self.assertEqual(1, len(calls_requests_put))
        request_put_args = calls_requests_put[0]['args']
        self.assertEqual('/publier/fichierIpns', request_put_args[0])

    def test_put_publier_repertoire(self):
        # identificateur_document = {'doc': 'DUMMY'}
        # ipns_key_name = 'cle IPNS DUMMY'
        # self.res_data['ipns_cle_chiffree'] = multibase.encode('base64', b'abcd1234').decode('utf-8')
        # self.res_data['contenu_gzip'] = b'mon contenu binaire DUMMY pas gzippe'

        cdns = [self.cdn]

        remote_path_fichier = '/mon/path/dummy'
        file_pointer = BytesIO(b'dummy bytes 01234')
        mimetype_fichier = 'application/octet-stream'
        fichiers = [
            # ('files', (remote_path_fichier, file_pointer, mimetype_fichier))
            {'remote_path': remote_path_fichier, 'fp': file_pointer, 'mimetype': mimetype_fichier}
        ]
        # fichiers = [{'remote_path': remote_path, 'fp': fp_bytesio, 'mimetype': mimetype}]

        self.http_publication.put_publier_repertoire(cdns, fichiers)

        # Verifier
        calls_requests_put = self.http_publication.calls_requests_put
        self.assertEqual(1, len(calls_requests_put))
        request_put_args = calls_requests_put[0]['args']
        self.assertEqual('/publier/repertoire', request_put_args[0])


class RessourcesPublicationTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()
        self.cascade = StubCascade(self.contexte)

        self.ressources_publication = RessourcesPublication(self.cascade)

        # self.securite = Constantes.SECURITE_PUBLIC
        # self.cdn = {
        #     ConstantesPublication.CHAMP_CDN_ID: 'CDN-1',
        #     ConstantesPublication.CHAMP_TYPE_CDN: 'CDN DUMMY',
        # }
        #
        # self.res_data = {
        #     Constantes.DOCUMENT_INFODOC_LIBELLE: 'DUMMY',
        #     ConstantesPublication.CHAMP_SECTION_ID: 'abcd-1234',
        # }

    def test_maj_ressource_mapping(self):
        self.contexte.document_dao.valeurs_find.append([])
        self.contexte.document_dao.valeurs_find.append({})
        self.contexte.document_dao.valeurs_update.append('DUMMY resultat')

        # Mocks
        def trouver_sites_avec_cdns_actifs():
            return {
                'DUMMY-site': {
                    ConstantesPublication.CHAMP_SITE_ID: 'DUMMY-site',
                    ConstantesPublication.CHAMP_IPNS_ID: 'DUMMY-ipns',
                    ConstantesPublication.CHAMP_LISTE_DOMAINES: [
                        'https://DUMMY-1'
                    ]
                }
            }

        doc_res_sites = [
            {
                ConstantesPublication.CHAMP_CONTENU_SIGNE: {
                    'cdns': [{
                        ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
                        ConstantesPublication.CHAMP_TYPE_CDN: 'DUMMY-type',
                        ConstantesPublication.CHAMP_ACCESS_POINT_URL: 'https://DUMMY',
                    }],
                },

            }
        ]

        def preparer_siteconfig_publication(*args, **kwargs):
            return doc_res_sites.pop()

        self.ressources_publication.trouver_sites_avec_cdns_actifs = trouver_sites_avec_cdns_actifs
        self.ressources_publication.preparer_siteconfig_publication = preparer_siteconfig_publication

        doc_mapping = self.ressources_publication.maj_ressource_mapping()
        self.assertEqual('DUMMY resultat', doc_mapping)

        calls_find_update = self.contexte.document_dao.calls_find_update
        update_args_1 = calls_find_update[0]['args']

        self.assertDictEqual({'_mg-libelle': 'mapping'}, update_args_1[0])

        self.assertDictEqual(
            {'https://DUMMY-1': {'site_id': 'DUMMY-site', 'ipns_id': 'DUMMY-ipns'}},
            update_args_1[1]['$set']['contenu']['sites']
        )

        self.assertDictEqual(
            {'site_id': 'DUMMY-site', 'ipns_id': 'DUMMY-ipns'},
            update_args_1[1]['$set']['contenu']['site_defaut']
        )

        self.assertDictEqual(
            {'cdn_id': 'DUMMY-cdn', 'type_cdn': 'DUMMY-type', 'access_point_url': 'https://DUMMY'},
            update_args_1[1]['$set']['contenu']['cdns'][0]
        )

    def test_maj_ressources_site(self):
        self.ressources_publication.maj_ressources_site()

    def test_maj_ressources_page(self):
        self.ressources_publication.maj_ressources_page()

    def test_maj_ressources_fuuids_vide(self):
        fuuids_info = {}
        sites = None
        public = False

        self.ressources_publication.maj_ressources_fuuids(fuuids_info, sites, public=True)

        invalider_ressources_sections_fichiers_calls = self.cascade.invalider_ressources_sections_fichiers_calls
        self.assertEqual(1, len(invalider_ressources_sections_fichiers_calls))

    def test_maj_ressources_fuuids_1fichier(self):
        fuuids_info = {
            'DUMMY-1': {
                ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES: {
                    'DUMMY-1': 'DUMMY-MIMETYPE'
                }
            }
        }
        sites = None

        self.contexte.document_dao.valeurs_update.append({
            'sites': []
        })

        self.ressources_publication.maj_ressources_fuuids(fuuids_info, sites, public=True)

        invalider_ressources_sections_fichiers_calls = self.cascade.invalider_ressources_sections_fichiers_calls
        self.assertEqual(1, len(invalider_ressources_sections_fichiers_calls))

        calls_find_update = self.contexte.document_dao.calls_find_update
        self.assertDictEqual({'_mg-libelle': 'fichier', 'fuuid': 'DUMMY-1'}, calls_find_update[0]['args'][0])
        self.assertDictEqual({'collections': [], 'public': True, 'mimetype': 'DUMMY-MIMETYPE'}, calls_find_update[0]['args'][1]['$set'])

    def test_get_ressource_collection_fichiers(self):
        uuid_collection = 'DUMMY-uuid'

        self.contexte.document_dao.valeurs_find.append('DUMMY-resultat')

        res_collection = self.ressources_publication.get_ressource_collection_fichiers(uuid_collection)

        self.assertEqual('DUMMY-resultat', res_collection)

    def test_trouver_ressources_manquantes(self):
        # Sites
        self.contexte.document_dao.valeurs_find.append([{
            ConstantesPublication.CHAMP_SITE_ID: 'DUMMY-site'
        }])
        # Sections
        self.contexte.document_dao.valeurs_find.append([{
            ConstantesPublication.CHAMP_SECTION_ID: 'DUMMY-section',
            ConstantesPublication.CHAMP_TYPE_SECTION: 'DUMMY-type-section',
        }])

        self.contexte.document_dao.valeurs_update.append('DUMMY valeur 1')
        self.contexte.document_dao.valeurs_update.append('DUMMY valeur 2')

        self.ressources_publication.trouver_ressources_manquantes()

        calls_update = self.contexte.document_dao.calls_update
        self.assertEqual(2, len(calls_update))

    def test_identifier_ressources_fichiers(self):
        self.contexte.document_dao.valeurs_find.append([{
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'DUMMY-type',
            ConstantesPublication.CHAMP_SECTION_ID: 'DUMMY-section',
            ConstantesPublication.CHAMP_TYPE_SECTION: 'DUMMY-type'
        }])

        self.contexte.document_dao.valeurs_update.append(None)

        self.ressources_publication.identifier_ressources_fichiers()

        calls_update = self.contexte.document_dao.calls_update
        self.assertEqual(1, len(calls_update))

    def test_identifier_ressources_fichiers_page(self):
        self.contexte.document_dao.valeurs_find.append([{
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'page',
            ConstantesPublication.CHAMP_SECTION_ID: 'DUMMY-section',
            ConstantesPublication.CHAMP_TYPE_SECTION: 'DUMMY-type'
        }])

        self.contexte.document_dao.valeurs_update.append(None)

        mock_call = dict()

        def mock_maj_ressources_page(*args, **kwargs):
            mock_call['args'] = args
            mock_call['kwargs'] = kwargs

        self.ressources_publication.maj_ressources_page = mock_maj_ressources_page

        self.ressources_publication.identifier_ressources_fichiers()

        calls_update = self.contexte.document_dao.calls_update
        self.assertEqual(1, len(calls_update))
        self.assertDictEqual({'section_id': 'DUMMY-section'}, mock_call['args'][0])

    def test_identifier_ressources_fichiers_fichiers(self):
        self.contexte.document_dao.valeurs_find.append([{
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'fichiers',
            ConstantesPublication.CHAMP_SECTION_ID: 'DUMMY-section',
            ConstantesPublication.CHAMP_TYPE_SECTION: 'DUMMY-type'
        }])

        self.contexte.document_dao.valeurs_update.append(None)

        mock_call = dict()

        def mock_maj_ressources(*args, **kwargs):
            mock_call['args'] = args
            mock_call['kwargs'] = kwargs

        self.ressources_publication.maj_ressource_avec_fichiers = mock_maj_ressources

        self.ressources_publication.identifier_ressources_fichiers()

        calls_update = self.contexte.document_dao.calls_update
        self.assertEqual(1, len(calls_update))
        self.assertEqual('DUMMY-section', mock_call['args'][0])

    def test_maj_ressource_avec_fichiers(self):
        section_id = 'DUMMY-section'

        self.cascade.site[ConstantesPublication.CHAMP_LISTE_CDNS] = ''

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_SITE_ID: 'DUMMY-site',
            'collections': ['UUID-collection1']
        })

        self.contexte.document_dao.valeurs_find.append({
        })

        self.contexte.document_dao.valeurs_update.append('DUMMY valeur')

        self.ressources_publication.maj_ressource_avec_fichiers(section_id)

        calls_update = self.contexte.document_dao.calls_update
        self.assertEqual(1, len(calls_update))
        calls_args = calls_update[0]['args']
        self.assertDictEqual({'_mg-libelle': 'collection_fichiers', 'uuid': 'UUID-collection1'}, calls_args[0])
        self.assertDictEqual({'sites': {'$each': ['DUMMY-site']}}, calls_args[1]['$addToSet'])

    def test_maj_ressource_collection_fichiers(self):
        site_ids = ['SITE-1']
        info_collection = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: 'DUMMY-uuid',
        }
        liste_fichiers = []

        self.contexte.document_dao.valeurs_find.append([])
        self.contexte.document_dao.valeurs_update.append([])

        self.ressources_publication.maj_ressource_collection_fichiers(site_ids, info_collection, liste_fichiers)

        calls_find_update = self.contexte.document_dao.calls_find_update

        self.assertEqual(1, len(calls_find_update))

    def test_trouver_info_fuuid_fichiers_vide(self):
        fuuids = list()
        self.contexte.document_dao.valeurs_find.append([])

        fuuids_info = self.ressources_publication.trouver_info_fuuid_fichiers(fuuids)

        self.assertEqual(0, len(fuuids_info))

    def test_trouver_info_fuuid_fichiers_1fichier(self):
        fuuids = list()
        self.contexte.document_dao.valeurs_find.append([
            {'fuuid': 'FUUID-1'}
        ])

        fuuids_info = self.ressources_publication.trouver_info_fuuid_fichiers(fuuids)

        self.assertEqual(1, len(fuuids_info))
        self.assertDictEqual({'public': False, 'mimetype': None}, fuuids_info['FUUID-1'])

    def test_trouver_info_fuuid_fichiers_cid(self):
        fuuids = list()
        self.contexte.document_dao.valeurs_find.append([
            {'fuuid': 'FUUID-1', 'cid': 'CID-1'}
        ])

        fuuids_info = self.ressources_publication.trouver_info_fuuid_fichiers(fuuids)

        self.assertEqual(1, len(fuuids_info))
        self.assertDictEqual({'public': False, 'mimetype': None, 'cid': 'CID-1'}, fuuids_info['FUUID-1'])

    def test_reset_ressources(self):
        params = {}
        self.contexte.document_dao.update_result.matched_count_value = 1

        resultat = self.ressources_publication.reset_ressources(params)

        self.assertEqual(1, resultat)

        calls_update = self.contexte.document_dao.calls_update

        self.assertEqual(1, len(calls_update))

    def test_reset_ressources_params(self):
        params = {
            'inclure': ['DUMMY-1'],
            'ignorer': ['DUMMY-2'],
        }
        self.contexte.document_dao.update_result.matched_count_value = 1

        resultat = self.ressources_publication.reset_ressources(params)

        self.assertEqual(1, resultat)

        calls_update = self.contexte.document_dao.calls_update

        self.assertEqual(1, len(calls_update))

        args_params = calls_update[0]['args'][0]
        self.assertDictEqual({'_mg-libelle': {'$in': ['DUMMY-1'], '$nin': ['DUMMY-2']}}, args_params)

    def test_sauvegarder_contenu_gzip(self):
        col_fichiers = {
            'contenu': {'valeur': 'du contenu'}
        }
        filtre_res = {'param': 'DUMMY'}
        self.contexte.document_dao.valeurs_update.append('DUMMY')

        resultat = self.ressources_publication.sauvegarder_contenu_gzip(col_fichiers, filtre_res)
        self.assertEqual('DUMMY', resultat)

        preparer_enveloppe_calls = self.cascade.preparer_enveloppe_calls
        calls_find_update = self.contexte.document_dao.calls_find_update

        self.assertEqual(1, len(preparer_enveloppe_calls))
        self.assertEqual(1, len(calls_find_update))

    def test_preparer_json_gzip(self):
        contenu_dict = {}
        resultat = self.ressources_publication.preparer_json_gzip(contenu_dict)
        self.assertTrue(isinstance(resultat, bytes))
        self.assertEqual(22, len(resultat))  # Verifier bytes

    def test_preparer_siteconfig_publication_sansdate(self):
        site_id = 'DUMMY-site'

        self.contexte.document_dao.valeurs_find.append({})

        # Site
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_LISTE_CDNS: []
        })

        self.contexte.document_dao.valeurs_find.append({})  # CDNs
        self.contexte.document_dao.valeurs_find.append([])  # CIDS

        self.contexte.document_dao.valeurs_update.append({'contenu': {'_id': 'DUMMY-contenu'}})  # Site

        self.contexte.document_dao.valeurs_update.append('reponse DUMMY')  # Site

        res_site = self.ressources_publication.preparer_siteconfig_publication(site_id)
        self.assertEqual('reponse DUMMY', res_site)

        preparer_enveloppe_calls = self.cascade.preparer_enveloppe_calls
        calls_find_update = self.contexte.document_dao.calls_find_update

        self.assertEqual(1, len(preparer_enveloppe_calls))
        self.assertEqual(2, len(calls_find_update))

    def test_preparer_siteconfig_publication_avecdate(self):
        site_id = 'DUMMY-site'

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_DATE_SIGNATURE: 'DUMMY-date'
        })

        # Site
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_LISTE_CDNS: []
        })

        self.contexte.document_dao.valeurs_find.append({})  # CDNs
        self.contexte.document_dao.valeurs_find.append([])  # CIDS

        self.contexte.document_dao.valeurs_update.append({'contenu': {'_id': 'DUMMY-contenu'}})  # Site

        self.contexte.document_dao.valeurs_update.append('reponse DUMMY')  # Site

        res_site = self.ressources_publication.preparer_siteconfig_publication(site_id)
        self.assertDictEqual({'date_signature': 'DUMMY-date'}, res_site)

        preparer_enveloppe_calls = self.cascade.preparer_enveloppe_calls
        calls_find_update = self.contexte.document_dao.calls_find_update

        self.assertEqual(0, len(preparer_enveloppe_calls))
        self.assertEqual(0, len(calls_find_update))

    def test_detecter_changement_collection_nouvelle(self):
        contenu_collection = {
            'collection': {
                'uuid': 'DUMMY-uuid',
            },
            'documents': []
        }
        self.contexte.document_dao.valeurs_find.append(None)  # Aucune collection

        resultat = self.ressources_publication.detecter_changement_collection(contenu_collection)

        self.assertTrue(resultat)

    def test_detecter_changement_collection_existante_vide(self):
        contenu_collection = {
            'collection': {
                'uuid': 'DUMMY-uuid',
            },
            'documents': [],  # Liste documents vide
        }
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CONTENU_SIGNE: {
                'DUMMY-contenu': True,
                'fuuids': {},
            }
        })  # Collection vide

        resultat = self.ressources_publication.detecter_changement_collection(contenu_collection)

        self.assertFalse(resultat)

    def test_detecter_changement_collection_existante_identique(self):
        contenu_collection = {
            'collection': {
                'uuid': 'DUMMY-uuid',
            },
            'documents': [{
                ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: [
                    'DUMMY-fuuid-1'
                ],
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE: 'DUMMY-fuuid-1',
            }]
        }
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CONTENU_SIGNE: {
                'DUMMY-contenu': True,
                'fuuids': {
                    'DUMMY-fuuid-1': 'contenu-dummy'
                },
            }
        })  # Collection vide

        resultat = self.ressources_publication.detecter_changement_collection(contenu_collection)

        self.assertFalse(resultat)

    def test_detecter_changement_collection_existante_nouveau(self):
        contenu_collection = {
            'collection': {
                'uuid': 'DUMMY-uuid',
            },
            'documents': [{
                ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: [
                    'DUMMY-fuuid-1',
                    'DUMMY-fuuid-2'
                ],
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE: 'DUMMY-fuuid-1',
            }]
        }
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CONTENU_SIGNE: {
                'DUMMY-contenu': True,
                'fuuids': {
                    'DUMMY-fuuid-1': 'contenu-dummy'
                },
            }
        })  # Collection vide

        resultat = self.ressources_publication.detecter_changement_collection(contenu_collection)

        self.assertTrue(resultat)

    def test_detecter_changement_collection_existante_retire(self):
        contenu_collection = {
            'collection': {
                'uuid': 'DUMMY-uuid',
            },
            'documents': [{
                ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: [
                    'DUMMY-fuuid-1',
                ],
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE: 'DUMMY-fuuid-1',
            }]
        }
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CONTENU_SIGNE: {
                'DUMMY-contenu': True,
                'fuuids': {
                    'DUMMY-fuuid-1': 'contenu-dummy',
                    'DUMMY-fuuid-2': 'contenu-dummy',
                },
            }
        })  # Collection vide

        resultat = self.ressources_publication.detecter_changement_collection(contenu_collection)

        self.assertTrue(resultat)

    def test_ajouter_site_fichiers(self):
        uuid_collection = 'DUMMY-uuid'
        sites = ['DUMMY-site']

        self.contexte.document_dao.valeurs_update.append('DUMMY')

        self.ressources_publication.ajouter_site_fichiers(uuid_collection, sites)

        calls_update = self.contexte.document_dao.calls_update

        self.assertEqual(1, len(calls_update))
        args_update = calls_update[0]['args']
        self.assertDictEqual({'$addToSet': {'sites': {'$each': ['DUMMY-site']}}}, args_update[1])

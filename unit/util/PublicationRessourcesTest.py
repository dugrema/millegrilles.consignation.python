import json
import multibase

from unit.helpers.TestBaseContexte import TestCaseContexte
from io import BytesIO

from millegrilles import Constantes
from millegrilles.util.PublicationRessources import InvalidateurRessources, TriggersPublication, HttpPublication, \
    RessourcesPublication, GestionnaireCascadePublication
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
        self.identifier_ressources_fichiers_calls = list()
        self.reset_ressources_encours_calls = list()
        self.emettre_evenements_downstream_calls = list()

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

    def identifier_ressources_fichiers(self, *args, **kwargs):
        self.identifier_ressources_fichiers_calls.append({'args': args, 'kwargs': kwargs})

    def reset_ressources_encours(self, *args, **kwargs):
        self.reset_ressources_encours_calls.append({'args': args, 'kwargs': kwargs})

    def emettre_evenements_downstream(self, *args, **kwargs):
        self.emettre_evenements_downstream_calls.append({'args': args, 'kwargs': kwargs})

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

    @property
    def triggers_publication(self):
        # Mock
        return self


class StubRessourcesPublication:

    def sauvegarder_contenu_gzip(self, *args, **kwargs):
        res_data = args[0]
        res_data = res_data.copy()
        res_data[ConstantesPublication.CHAMP_CONTENU_GZIP] = b'contenu gzip dummy'
        return res_data


class StubInvalidateur:

    def __init__(self):
        self.marquer_ressource_complete_calls = list()
        self.invalider_ressources_sections_fichiers_calls = list()

    def marquer_ressource_complete(self, *args, **kwargs):
        self.marquer_ressource_complete_calls.append({'args': args, 'kwargs': kwargs})

    def invalider_ressources_sections_fichiers(self, *args, **kwargs):
        self.invalider_ressources_sections_fichiers_calls.append({'args': args, 'kwargs': kwargs})


class StubTriggerPublication:

    def __init__(self):
        self.marquer_ressource_complete_calls = list()
        self.preparer_sitesparcdn_calls = list()
        self.emettre_publier_webapps_calls = list()
        self.emettre_publier_uploadpages_calls = list()
        self.emettre_publier_configuration_calls = list()
        self.emettre_publier_mapping_calls = list()
        self.trigger_traitement_collections_fichiers_calls = list()
        self.trigger_publication_fichiers_calls = list()
        self.emettre_publier_collectionfichiers_calls = list()

        self.sites_par_cdn = list()
        self.compteur_publier_webapps = 0
        self.compteur_publier_uploadpages = 0
        self.compteur_publier_configuration = 0
        self.compteur_publier_mapping = 0
        self.compteur_trigger_collections_fichiers = 0
        self.compteur_trigger_fichiers = 0
        self.compteur_publier_collectionfichiers = 0

    def emettre_evenements_downstream(self, *args, **kwargs):
        self.marquer_ressource_complete_calls.append({'args': args, 'kwargs': kwargs})

    def preparer_sitesparcdn(self, *args, **kwargs):
        self.preparer_sitesparcdn_calls.append({'args': args, 'kwargs': kwargs})
        return self.sites_par_cdn.pop()

    def emettre_publier_webapps(self, *args, **kwargs):
        self.emettre_publier_webapps_calls.append({'args': args, 'kwargs': kwargs})
        return self.compteur_publier_webapps

    def emettre_publier_uploadpages(self, *args, **kwargs):
        self.emettre_publier_uploadpages_calls.append({'args': args, 'kwargs': kwargs})
        return self.compteur_publier_uploadpages

    def emettre_publier_configuration(self, *args, **kwargs):
        self.emettre_publier_configuration_calls.append({'args': args, 'kwargs': kwargs})
        return self.compteur_publier_configuration

    def emettre_publier_mapping(self, *args, **kwargs):
        self.emettre_publier_mapping_calls.append({'args': args, 'kwargs': kwargs})
        return self.compteur_publier_mapping

    def trigger_traitement_collections_fichiers(self, *args, **kwargs):
        self.trigger_traitement_collections_fichiers_calls.append({'args': args, 'kwargs': kwargs})
        return self.compteur_trigger_collections_fichiers

    def trigger_publication_fichiers(self, *args, **kwargs):
        self.trigger_publication_fichiers_calls.append({'args': args, 'kwargs': kwargs})
        return self.compteur_trigger_fichiers

    def emettre_publier_collectionfichiers(self, *args, **kwargs):
        self.emettre_publier_collectionfichiers_calls.append({'args': args, 'kwargs': kwargs})
        return self.compteur_publier_collectionfichiers


class StubGestionnaireDomaine:

    def __init__(self, contexte):
        self.__contexte = contexte
        self.demarrer_processus_calls = list()
        self.transmettre_commande_calls = list()

    def preparer_enveloppe(self, *args, **kwargs):
        return args[0]

    def transmettre_commande(self, *args, **kwargs):
        self.transmettre_commande_calls.append({'args': args, 'kwargs': kwargs})

    @property
    def contexte(self):
        return self.__contexte

    @property
    def document_dao(self):
        return self.__contexte.document_dao

    @property
    def generateur_transactions(self):
        return self

    def demarrer_processus(self, *args, **kwargs):
        self.demarrer_processus_calls.append({'args': args, 'kwargs': kwargs})


class HttpPublicationStub:

    def __init__(self, *args, **kwargs):
        self.calls_requests_put = list()
        self.put_publier_fichier_ipns_calls = list()
        self.put_publier_repertoire_calls = list()
        self.put_fichier_ipns_calls = list()

    def requests_put(self, *args, **kwargs):
        self.calls_requests_put.append({
            'args': args,
            'kwargs': kwargs,
        })
        return RequestsReponse()

    def put_publier_fichier_ipns(self, *args, **kwargs):
        self.put_publier_fichier_ipns_calls.append({
            'args': args,
            'kwargs': kwargs,
        })
        return RequestsReponse()

    def put_fichier_ipns(self, *args, **kwargs):
        self.put_fichier_ipns_calls.append({
            'args': args,
            'kwargs': kwargs,
        })
        return RequestsReponse()

    def put_publier_repertoire(self, *args, **kwargs):
        self.put_publier_repertoire_calls.append({
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
        compteur = self.trigger.trigger_traitement_collections_fichiers()
        self.assertEqual(1, compteur)

        # Verifier resultats
        # update_calls = self.contexte.document_dao.calls_update
        # demarrer_processus_calls = self.cascade.demarrer_processus_calls
        #
        # self.assertEqual(1, len(update_calls))
        # self.assertEqual(1, len(demarrer_processus_calls))
        #
        # self.assertEqual('abcd-1234', update_calls[0]['args'][0]['uuid'])
        # self.assertEqual('collection_fichiers', update_calls[0]['args'][0]['_mg-libelle'])
        # self.assertEqual('en_cours', update_calls[0]['args'][1]['$set']['preparation_ressources'])

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
        site_id = 'DUMMY-site'

        # self.contexte.document_dao.valeurs_find.append({
        #     'site_id': 'DUMMY-site',
        # })

        # # section fichiers
        # self.contexte.document_dao.valeurs_find.append([{
        #     'section_id': 'DUMMY-section',
        #     'collections': ['DUMMY-uuid'],
        # }])

        # collection_fichiers
        self.contexte.document_dao.valeurs_find.append([{
            'uuid': 'DUMMY-uuid',
            'contenu': {
                'securite': Constantes.SECURITE_PUBLIC,
            },
        }])

        compteur = self.trigger.emettre_publier_collectionfichiers(cdn_id)
        self.assertEqual(1, compteur)

        contenu_gzip_calls = self.cascade.sauvegarder_contenu_gzip_calls
        ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls

        self.assertEqual(1, len(contenu_gzip_calls))
        self.assertEqual(1, len(ressource_encours_calls))
        self.assertEqual(1, len(transmettre_commande_calls))

        gzip_call_args1 = contenu_gzip_calls[0]['args']
        self.assertEqual('DUMMY-uuid', gzip_call_args1[0]['uuid'])

        ressource_args1 = ressource_encours_calls[0]['args']
        # ressource_args2 = ressource_encours_calls[1]['args']

        self.assertEqual('DUMMY-CDN', ressource_args1[0])
        self.assertDictEqual({'_mg-libelle': 'collection_fichiers', 'uuid': 'DUMMY-uuid'}, ressource_args1[1])

        # self.assertEqual('DUMMY-CDN', ressource_args2[0])
        # self.assertDictEqual({'_mg-libelle': 'fichier', 'distribution_complete': {'$not': {'$all': ['DUMMY-CDN']}}, 'collections': {'$all': ['DUMMY-uuid']}}, ressource_args2[1])

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

        self.assertEqual(0, len(ressource_encours_calls))
        self.assertEqual(0, len(transmettre_commande_calls))

        # resource_args1 = ressource_encours_calls[0]['args']
        # transmettre_commande_args1 = transmettre_commande_calls[0]['args']

        self.assertEqual(0, compte_commandes)
        # self.assertEqual('commande.Publication.publierUploadSiteConfiguration', transmettre_commande_args1[1])
        # self.assertDictEqual({'site_id': 'site-DUMMY', 'cdn_id': 'DUMMY-CDN', 'remote_path': 'data/sites/site-DUMMY.json.gz', 'mimetype': 'application/json', 'content_encoding': 'gzip', 'max_age': 0}, transmettre_commande_args1[0])

        self.assertEqual(0, len(siteconfig_calls))
        # self.assertDictEqual({'args': ('DUMMY-CDN', 'site-DUMMY'), 'kwargs': {}}, siteconfig_calls[0])

        # self.assertEqual('DUMMY-CDN', resource_args1[0])
        # self.assertDictEqual({'_mg-libelle': 'siteconfig', 'site_id': 'site-DUMMY'}, resource_args1[1])

    def test_emettre_publier_configuration_site_dist_encours(self):
        cdn_id = 'DUMMY-CDN'
        site_id = 'DUMMY-site'

        self.site[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES] = {'DUMMY-CDN': True}
        self.contexte.document_dao.valeurs_find.append([self.site])

        compte_commandes = self.trigger.emettre_publier_configuration(cdn_id, site_id)

        ressource_encours_calls = self.cascade.marquer_ressource_encours_calls
        transmettre_commande_calls = self.cascade.transmettre_commande_calls
        siteconfig_calls = self.cascade.preparer_siteconfig_publication_calls

        self.assertEqual(1, compte_commandes)
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
        self.assertEqual('millegrilles_util_PublicationRessources:ProcessusCreerCleIpnsVitrine', processus_calls[0]['args'][0])

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
        self.http_publication = HttpPublication(self.cascade, configuration)
        self.http_publication.requests_put = self.requests_put

        self.securite = Constantes.SECURITE_PUBLIC
        self.cdn = {
            ConstantesPublication.CHAMP_CDN_ID: 'CDN-1',
            ConstantesPublication.CHAMP_TYPE_CDN: 'CDN DUMMY',
        }

        self.res_data = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'DUMMY',
            ConstantesPublication.CHAMP_SECTION_ID: 'abcd-1234',
        }

        self.calls_requests_put = list()

    def requests_put(self, *args, **kwargs):
        self.calls_requests_put.append({
            'args': args,
            'kwargs': kwargs,
        })
        return RequestsReponse()

    def test_put_publier_fichier_ipns_nokey(self):
        self.http_publication.put_publier_fichier_ipns(self.cdn, self.res_data, self.securite)

        # Verifier
        demarrer_processus_calls = self.cascade.demarrer_processus_calls

        self.assertEqual('millegrilles_util_PublicationRessources:ProcessusPublierCleEtFichierIpns', demarrer_processus_calls[0]['args'][0])
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
        calls_requests_put = self.calls_requests_put
        self.assertEqual(1, len(calls_requests_put))
        request_put_args = calls_requests_put[0]['args']
        self.assertEqual('publier/fichierIpns', request_put_args[0])

    def test_put_fichier_ipns(self):
        identificateur_document = {'doc': 'DUMMY'}
        ipns_key_name = 'cle IPNS DUMMY'
        self.res_data['ipns_cle_chiffree'] = multibase.encode('base64', b'abcd1234').decode('utf-8')
        self.res_data['contenu_gzip'] = b'mon contenu binaire DUMMY pas gzippe'

        self.http_publication.put_fichier_ipns(self.cdn, identificateur_document, ipns_key_name, self.res_data, self.securite)

        # Verifier
        calls_requests_put = self.calls_requests_put
        self.assertEqual(1, len(calls_requests_put))
        request_put_args = calls_requests_put[0]['args']
        self.assertEqual('publier/fichierIpns', request_put_args[0])

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
        calls_requests_put = self.calls_requests_put
        self.assertEqual(1, len(calls_requests_put))
        request_put_args = calls_requests_put[0]['args']
        self.assertEqual('publier/repertoire', request_put_args[0])


class RessourcesPublicationTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()
        self.cascade = StubCascade(self.contexte)

        self.ressources_publication = RessourcesPublication(self.cascade)

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
                    Constantes.DOCUMENT_INFODOC_SECURITE: Constantes.SECURITE_PUBLIC,
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
            {'https://DUMMY-1': {'site_id': 'DUMMY-site', 'ipns_id': 'DUMMY-ipns', 'securite': '1.public'}},
            update_args_1[1]['$set']['contenu']['sites']
        )

        self.assertDictEqual(
            {'site_id': 'DUMMY-site', 'ipns_id': 'DUMMY-ipns', 'securite': '1.public'},
            update_args_1[1]['$set']['contenu']['site_defaut']
        )

        self.assertDictEqual(
            {'cdn_id': 'DUMMY-cdn', 'type_cdn': 'DUMMY-type', 'access_point_url': 'https://DUMMY'},
            update_args_1[1]['$set']['contenu']['cdns'][0]
        )

    def test_maj_ressources_site(self):

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_SITE_ID: 'DUMMY-site'
        })

        self.contexte.document_dao.valeurs_update.append('DUMMY resultat')

        # Mocks
        def mapper_cdns_pour_site(*args, **kwargs):
            return [{'type_cdn': 'DUMMY-type', 'cdn_id': 'DUMMY-cdn', 'access_point_url': 'https://DUMMY'}]

        def mapper_site_ipfs(*args, **kwargs):
            return 'DUMMY-cid', {'DUMMY-uuid': 'DUMMY-cid-1', 'DUMMY-section': 'DUYYM-cid-2'}

        self.ressources_publication.mapper_cdns_pour_site = mapper_cdns_pour_site
        self.ressources_publication.mapper_site_ipfs = mapper_site_ipfs

        params = {ConstantesPublication.CHAMP_SITE_ID: 'DUMMY-site'}

        doc_site = self.ressources_publication.maj_ressources_site(params)
        self.assertEqual('DUMMY resultat', doc_site)

        find_update = self.contexte.document_dao.calls_find_update[0]['args'][1]

        self.assertDictEqual(
            {'distribution_complete': True, 'distribution_public_complete': True, 'distribution_erreur': True,
             'distribution_maj': True, 'date_signature': True},
            find_update['$unset']
        )
        self.assertDictEqual(
            {'contenu': {'type_section': 'siteconfig', 'site_id': 'DUMMY-site', 'cdns': [
                {'type_cdn': 'DUMMY-type', 'cdn_id': 'DUMMY-cdn', 'access_point_url': 'https://DUMMY'}],
                         'cid': 'DUMMY-cid', 'ipfs_map': {'DUMMY-uuid': 'DUMMY-cid-1', 'DUMMY-section': 'DUYYM-cid-2'}},
             'sites': ['DUMMY-site']},
            find_update['$set']
        )

    def test_maj_ressources_page(self):
        params = {ConstantesPublication.CHAMP_SECTION_ID: 'DUMMY-section'}

        self.contexte.document_dao.valeurs_find.append([
            {'fuuid': 'DUMMY-fuuid-1'},
        ])

        self.cascade.site['securite'] = Constantes.SECURITE_PUBLIC

        self.contexte.document_dao.valeurs_update.append('DUMMY reponse')

        def formatter_parties_page(*args, **kwargs):
            return {}, 'DUMMY-liste-partiespages', 'DUMMY-site'

        def formatter_fuuids_page(*args, **kwargs):
            return 'DUMMY-liste-fuuids'

        self.ressources_publication.formatter_parties_page = formatter_parties_page
        self.ressources_publication.formatter_fuuids_page = formatter_fuuids_page

        doc_page = self.ressources_publication.maj_ressources_page(params)

        self.assertEqual('DUMMY reponse', doc_page)

        calls_find_update = self.contexte.document_dao.calls_find_update[0]['args'][1]

        self.assertDictEqual(
            {'contenu': {'type_section': 'page', 'section_id': 'DUMMY-section', 'parties_pages': 'DUMMY-liste-partiespages', 'fuuids': 'DUMMY-liste-fuuids'}, 'sites': ['DUMMY-site']},
            calls_find_update['$set']
        )

    def test_formatter_parties_page(self):
        section_id = 'DUMMY-section'

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_SECTION_ID: 'DUMMY-section',
            ConstantesPublication.CHAMP_SITE_ID: 'DUMMY-site',
            ConstantesPublication.CHAMP_PARTIES_PAGES: ['DUMMY-pp-1', 'DUMMY-pp-2']
        })

        self.contexte.document_dao.valeurs_find.append([
            {
                ConstantesPublication.CHAMP_PARTIEPAGE_ID: 'DUMMY-pp-1',
                'colonnes': [
                    {'media': {'fuuids': ['DUMMY-fuuid-1']}}
                ]
            },
            {
                ConstantesPublication.CHAMP_PARTIEPAGE_ID: 'DUMMY-pp-2',
                'media': {'fuuids': ['DUMMY-fuuid-2']}
            },
        ])

        fuuids_info, parties_page_ordonnees, site_id = self.ressources_publication.formatter_parties_page(section_id)

        self.assertEqual('DUMMY-section', section_id)

        self.assertDictEqual(
            {'DUMMY-fuuid-1': {'fuuids': ['DUMMY-fuuid-1']}, 'DUMMY-fuuid-2': {'fuuids': ['DUMMY-fuuid-2']}},
            fuuids_info
        )

        self.assertDictEqual(
            {'partiepage_id': 'DUMMY-pp-1', 'colonnes': [{'media': {'fuuids': ['DUMMY-fuuid-1']}}]},
            parties_page_ordonnees[0]
        )
        self.assertDictEqual(
            {'partiepage_id': 'DUMMY-pp-2', 'media': {'fuuids': ['DUMMY-fuuid-2']}},
            parties_page_ordonnees[1]
        )

    def test_formatter_fuuids_page(self):
        fuuids_info = {
            '0': {ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES: {
                'DUMMY-fuuid-1': 'DUMMY-mimetype-1',
                'DUMMY-fuuid-2': 'DUMMY-mimetype-2',
            }},
            '1': {ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES: {
                'DUMMY-fuuid-3': 'DUMMY-mimetype-3',
            }}
        }

        self.contexte.document_dao.valeurs_find.append([
            {'fuuid': 'DUMMY-fuuid-1'},
            {'fuuid': 'DUMMY-fuuid-2', 'public': True, 'cid_public': 'DUMMY-cid-public'},
            {'fuuid': 'DUMMY-fuuid-3', 'cid': 'DUMMY-cid'},
        ])

        fuuids = self.ressources_publication.formatter_fuuids_page(fuuids_info)

        self.assertDictEqual({'mimetype': 'DUMMY-mimetype-1'}, fuuids['DUMMY-fuuid-1'])
        self.assertDictEqual({'mimetype': 'DUMMY-mimetype-2', 'cid': 'DUMMY-cid-public', 'public': True}, fuuids['DUMMY-fuuid-2'])
        self.assertDictEqual({'mimetype': 'DUMMY-mimetype-3', 'cid': 'DUMMY-cid'}, fuuids['DUMMY-fuuid-3'])

    def test_mapper_cdns_pour_site(self):
        site_id = 'DUMMY-site'

        self.contexte.document_dao.valeurs_find.append({
            'listeCdn': ['DUMMY-cdn']
        })
        self.contexte.document_dao.valeurs_find.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            ConstantesPublication.CHAMP_TYPE_CDN: 'DUMMY-type',
            'accesPointUrl': 'https://DUMMY',
        }])

        mapping_cdns = self.ressources_publication.mapper_cdns_pour_site(site_id)

        self.assertDictEqual(
            {'type_cdn': 'DUMMY-type', 'cdn_id': 'DUMMY-cdn', 'access_point_url': 'https://DUMMY'},
            mapping_cdns[0]
        )

    def test_mapper_site_ipfs_cidsite(self):
        site_id = 'DUMMY-site'

        self.contexte.document_dao.valeurs_find.append([{
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            ConstantesPublication.CHAMP_CID: 'DUMMY-cid',
        }])

        cid_site, uuid_to_ipfs = self.ressources_publication.mapper_site_ipfs(site_id)

        self.assertEqual('DUMMY-cid', cid_site)
        self.assertEqual(0, len(uuid_to_ipfs))
        pass

    def test_mapper_site_ipfs_cid_uuids_byuuid(self):
        site_id = 'DUMMY-site'

        self.contexte.document_dao.valeurs_find.append([{
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'DUMMY-type',
            'uuid': 'DUMMY-uuid',
            ConstantesPublication.CHAMP_CID: 'DUMMY-cid',
        }])

        cid_site, uuid_to_ipfs = self.ressources_publication.mapper_site_ipfs(site_id)

        self.assertIsNone(cid_site)
        self.assertEqual(1, len(uuid_to_ipfs))
        self.assertDictEqual({'DUMMY-uuid': 'DUMMY-cid'}, uuid_to_ipfs)

    def test_mapper_site_ipfs_cid_uuids_bysectionid(self):
        site_id = 'DUMMY-site'

        self.contexte.document_dao.valeurs_find.append([{
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'DUMMY-type',
            'section_id': 'DUMMY-section',
            ConstantesPublication.CHAMP_CID: 'DUMMY-cid',
        }])

        cid_site, uuid_to_ipfs = self.ressources_publication.mapper_site_ipfs(site_id)

        self.assertIsNone(cid_site)
        self.assertEqual(1, len(uuid_to_ipfs))
        self.assertDictEqual({'DUMMY-section': 'DUMMY-cid'}, uuid_to_ipfs)

    def test_maj_ressources_fuuids_vide(self):
        fuuids_info = {}
        public = False

        self.ressources_publication.maj_ressources_fuuids(fuuids_info, public=public)

        calls_find_update = self.contexte.document_dao.calls_find_update
        self.assertEqual(0, len(calls_find_update))

    def test_maj_ressources_fuuids_1fichier(self):
        fuuids_info = {
            'DUMMY-1': {
                ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES: {
                    'DUMMY-1': 'DUMMY-MIMETYPE'
                }
            }
        }

        self.contexte.document_dao.valeurs_update.append({
            'sites': []
        })

        self.ressources_publication.maj_ressources_fuuids(fuuids_info, public=True)

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
        # Webapps
        self.contexte.document_dao.valeurs_find.append([{
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_WEBAPPS,
        }])

        self.contexte.document_dao.valeurs_update.append('DUMMY valeur 1')
        self.contexte.document_dao.valeurs_update.append('DUMMY valeur 2')
        self.contexte.document_dao.valeurs_update.append('DUMMY valeur 3')

        self.ressources_publication.trouver_ressources_manquantes()

        calls_update = self.contexte.document_dao.calls_update
        self.assertEqual(3, len(calls_update))

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
            return ['uuid-1']

        self.ressources_publication.maj_ressource_avec_fichiers = mock_maj_ressources

        self.ressources_publication.identifier_ressources_fichiers()

        calls_update = self.contexte.document_dao.calls_update
        demarrer_processus_calls = self.cascade.demarrer_processus_calls
        self.assertEqual(1, len(calls_update))
        self.assertEqual('DUMMY-section', mock_call['args'][0])
        self.assertEqual(1, len(demarrer_processus_calls))

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
        info_collection = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: 'DUMMY-uuid',
        }
        liste_fichiers = []

        self.contexte.document_dao.valeurs_find.append([])      # Liste fichiers avec CID
        self.contexte.document_dao.valeurs_update.append([])    # Creer fichiers manquants (liste info_collection)
        self.contexte.document_dao.valeurs_find.append([])      # Recharger tous les fichiers (existants et crees, avec CID et mimetype)

        self.ressources_publication.maj_ressource_collection_fichiers(info_collection, liste_fichiers)

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

        calls = list()

        def maj_ressources_site(*args, **kwargs):
            calls.append('maj_ressources_site')
            return {}

        def sauvegarder_contenu_gzip(*args, **kwargs):
            calls.append('sauvegarder_contenu_gzip')
            return 'reponse DUMMY'

        self.ressources_publication.maj_ressources_site = maj_ressources_site
        self.ressources_publication.sauvegarder_contenu_gzip = sauvegarder_contenu_gzip

        res_site = self.ressources_publication.preparer_siteconfig_publication(site_id)
        self.assertEqual('reponse DUMMY', res_site)

        self.assertEqual('maj_ressources_site', calls[0])
        self.assertEqual('sauvegarder_contenu_gzip', calls[1])

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
            },
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
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
            },
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
        })

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
            },
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
        })

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
            },
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
        })  # Collection vide

        resultat = self.ressources_publication.detecter_changement_collection(contenu_collection)

        self.assertTrue(resultat)


class GestionnaireCascadePublicationTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()
        # self.cascade = StubCascade(self.contexte)

        self.gestionnaire_domaine = StubGestionnaireDomaine(self.contexte)
        self.cascade = GestionnaireCascadePublication(self.gestionnaire_domaine, self.contexte)

        self.ressources_publication = StubRessourcesPublication()
        self.cascade.ressources_publication = self.ressources_publication

        self.invalidateur = StubInvalidateur()
        self.cascade.invalidateur_ressources = self.invalidateur

        self.trigger = StubTriggerPublication()
        self.cascade.triggers_publication = self.trigger

        # Wire stub http publication
        self.http_publication = HttpPublicationStub(self.cascade, self.contexte.configuration)
        self.cascade.http_publication = self.http_publication

    def test_commande_publier_upload_datasection_type_invalide(self):
        params = {
            'type_section': 'DUMMY-type',
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'dummy/type',
            'securite': Constantes.SECURITE_PUBLIC,
        }

        resultat = self.cascade.commande_publier_upload_datasection(params)
        self.assertDictEqual({'err': 'Type section inconnue: DUMMY-type'}, resultat)

    def test_commande_publier_upload_datasection_gzip_paspret(self):
        params = {
            'type_section': 'page',
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'dummy/type',
            'securite': Constantes.SECURITE_PUBLIC,
            'section_id': 'DUMMY-section',
        }

        self.contexte.document_dao.valeurs_find.append({})

        resultat = self.cascade.commande_publier_upload_datasection(params)

        self.assertDictEqual({'err': "Le contenu gzip de la section n'est pas pret. Section : {'_mg-libelle': 'page', 'section_id': 'DUMMY-section'}"}, resultat)

    def test_commande_publier_upload_datasection_page(self):
        params = {
            'type_section': 'page',
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'dummy/type',
            'securite': Constantes.SECURITE_PUBLIC,
            'section_id': 'DUMMY-section',
        }

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CONTENU_GZIP: b'contenu gzip dummy'
        })

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            ConstantesPublication.CHAMP_TYPE_CDN: 'sftp',
        })

        resultat = self.cascade.commande_publier_upload_datasection(params)

        self.assertDictEqual({"ok": True}, resultat)

        http_pub_args = self.http_publication.put_publier_repertoire_calls[0]['args']
        self.assertDictEqual({'cdn_id': 'DUMMY-cdn', 'type_cdn': 'sftp'}, http_pub_args[0][0])
        self.assertDictEqual(
            {'type_section': 'page', 'cdn_id': 'DUMMY-cdn', 'remote_path': '/DUMMY/path', 'mimetype': 'dummy/type', 'securite': '1.public', 'section_id': 'DUMMY-section', 'identificateur_document': {'_mg-libelle': 'page', 'section_id': 'DUMMY-section'}},
            http_pub_args[2]
        )

    def test_commande_publier_upload_datasection_fichiers(self):
        params = {
            'type_section': 'collection_fichiers',
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'dummy/type',
            'securite': Constantes.SECURITE_PUBLIC,
            'uuid_collection': 'DUMMY-uuid',
        }

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CONTENU_GZIP: b'contenu gzip dummy'
        })

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            ConstantesPublication.CHAMP_TYPE_CDN: 'sftp',
        })

        resultat = self.cascade.commande_publier_upload_datasection(params)

        self.assertDictEqual({"ok": True}, resultat)

        http_pub_args = self.http_publication.put_publier_repertoire_calls[0]['args']
        self.assertDictEqual({'cdn_id': 'DUMMY-cdn', 'type_cdn': 'sftp'}, http_pub_args[0][0])
        self.assertDictEqual(
            {'type_section': 'collection_fichiers', 'cdn_id': 'DUMMY-cdn', 'remote_path': '/DUMMY/path', 'mimetype': 'dummy/type', 'securite': '1.public', 'uuid_collection': 'DUMMY-uuid', 'identificateur_document': {'_mg-libelle': 'collection_fichiers', 'uuid': 'DUMMY-uuid'}},
            http_pub_args[2]
        )

    def test_commande_publier_upload_datasection_ipfs(self):
        params = {
            'type_section': 'page',
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'dummy/type',
            'securite': Constantes.SECURITE_PUBLIC,
            'section_id': 'DUMMY-section',
        }

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CONTENU_GZIP: b'contenu gzip dummy'
        })

        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            ConstantesPublication.CHAMP_TYPE_CDN: 'ipfs',
        })

        resultat = self.cascade.commande_publier_upload_datasection(params)

        self.assertDictEqual({"ok": True}, resultat)

        http_pub_args = self.http_publication.put_publier_repertoire_calls[0]['args']
        self.assertDictEqual({'cdn_id': 'DUMMY-cdn', 'type_cdn': 'ipfs'}, http_pub_args[0][0])
        self.assertDictEqual(
            {'type_section': 'page', 'cdn_id': 'DUMMY-cdn', 'remote_path': '/DUMMY/path', 'mimetype': 'dummy/type', 'securite': '1.public', 'section_id': 'DUMMY-section', 'identificateur_document': {'_mg-libelle': 'page', 'section_id': 'DUMMY-section'}, 'fichier_unique': True},
            http_pub_args[2]
        )

    def test_commande_publier_upload_siteconfiguration(self):
        params = {
            ConstantesPublication.CHAMP_SITE_ID: 'DUMMY-site',
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'DUMMY/mimetype',
        }

        # res_data
        self.contexte.document_dao.valeurs_find.append({})

        # CDN
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_TYPE_CDN: 'sftp'
        })

        resultat = self.cascade.commande_publier_upload_siteconfiguration(params)

        self.assertDictEqual({'ok': True}, resultat)

        call_put_args = self.cascade.http_publication.put_publier_repertoire_calls[0]['args']
        self.assertDictEqual({'type_cdn': 'sftp'}, call_put_args[0][0])
        self.assertDictEqual(
            {'site_id': 'DUMMY-site', 'cdn_id': 'DUMMY-cdn', 'remote_path': '/DUMMY/path', 'mimetype': 'DUMMY/mimetype', 'identificateur_document': {'_mg-libelle': 'siteconfig', 'site_id': 'DUMMY-site'}},
            call_put_args[2]
        )

    def test_commande_publier_upload_siteconfiguration_ipfs(self):
        params = {
            ConstantesPublication.CHAMP_SITE_ID: 'DUMMY-site',
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'DUMMY/mimetype',
        }

        # res_data
        self.contexte.document_dao.valeurs_find.append({})

        # CDN
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_TYPE_CDN: 'ipfs'
        })

        resultat = self.cascade.commande_publier_upload_siteconfiguration(params)

        self.assertDictEqual({'ok': True}, resultat)

        self.assertEqual(1, len(self.cascade.http_publication.put_publier_fichier_ipns_calls))

    def test_commande_publier_upload_mapping(self):
        params = {
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'DUMMY/type',
        }

        # res_data
        self.contexte.document_dao.valeurs_find.append({})

        # CDN
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_TYPE_CDN: 'DUMMY-type'
        })

        self.contexte.document_dao.valeurs_update.append('DUMMY resultat')

        resultat = self.cascade.commande_publier_upload_mapping(params)

        self.assertDictEqual({'ok': True}, resultat)

        call_put_args = self.cascade.http_publication.put_publier_repertoire_calls[0]['args']
        self.assertDictEqual({'type_cdn': 'DUMMY-type'}, call_put_args[0][0])
        self.assertDictEqual(
            {'cdn_id': 'DUMMY-cdn', 'remote_path': '/DUMMY/path', 'mimetype': 'DUMMY/type', 'identificateur_document': {'_mg-libelle': 'mapping'}},
            call_put_args[2]
        )

    def test_commande_publier_upload_mapping_ipfs(self):
        params = {
            'cdn_id': 'DUMMY-cdn',
            'remote_path': '/DUMMY/path',
            'mimetype': 'DUMMY/type',
        }

        # res_data
        self.contexte.document_dao.valeurs_find.append({})

        # CDN
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_TYPE_CDN: 'ipfs'
        })

        resultat = self.cascade.commande_publier_upload_mapping(params)

        self.assertDictEqual({'ok': True}, resultat)

        self.assertEqual(0, len(self.cascade.http_publication.calls_requests_put))
        self.assertEqual(1, len(self.cascade.invalidateur_ressources.marquer_ressource_complete_calls))

    def test_traiter_evenement_publicationfichier(self):
        params = {
            'identificateur_document': {'_id': 'DUMMY-id'},
            # 'cdn_ids': [],
            'cdn_id': 'DUMMY-cdn',
            'complete': True,
            'cid': 'DUMMY-cid',
        }

        calls_continuer = list()

        def continuer_publication(*args, **kwargs):
            calls_continuer.append(True)

        self.cascade.continuer_publication = continuer_publication

        self.contexte.document_dao.valeurs_update.append('DUMMY resultat')

        self.cascade.traiter_evenement_publicationfichier(params)

        calls_update = self.contexte.document_dao.calls_update
        args_update = calls_update[0]['args']

        self.assertTrue(calls_continuer[0])
        self.assertDictEqual({'_mg-libelle': 'fichier', '_id': 'DUMMY-id'}, args_update[0])
        self.assertDictEqual(
            {'$currentDate': {'_mg-derniere-modification': True, 'ipfs_publication': True},
             '$set': {'cid': 'DUMMY-cid'},
             '$unset': {'distribution_encours.DUMMY-cdn': True, 'distribution_progres.DUMMY-cdn': True,
                        'distribution_erreur.DUMMY-cdn': True}, '$addToSet': {'distribution_complete': 'DUMMY-cdn'}},
            args_update[1]
        )

        marquer_ressource_complete_calls = self.trigger.marquer_ressource_complete_calls
        self.assertEqual(1, len(marquer_ressource_complete_calls))

    def test_traiter_evenement_maj_fichier(self):
        params = {
            'colections': ['DUMMY-uuid-col']
        }
        self.cascade.traiter_evenement_maj_fichier(params)

        self.assertEqual(1, len(self.invalidateur.invalider_ressources_sections_fichiers_calls))

    def test_trigger_conditionnel_fichiers_completes_completefalse(self):
        params = {
            'complete': False,
            # 'err': None,
            'identificateur_document': {'_id': 'DUMMY-doc'}
        }
        self.cascade.trigger_conditionnel_fichiers_completes(params)

    def test_trigger_conditionnel_fichiers_completes_completetrue(self):
        params = {
            'complete': True,
            'identificateur_document': {'_id': 'DUMMY-doc'}
        }
        self.cascade.trigger_conditionnel_fichiers_completes(params)

    def test_trigger_conditionnel_fichiers_completes_fuuid(self):
        params = {
            'complete': True,
            'identificateur_document': {'fuuid': 'DUMMY-doc'}
        }

        self.contexte.document_dao.valeurs_aggregate.append([{'en_cours': 0}])

        calls_continuer = list()
        def continuer_publication(*args, **kwargs):
            calls_continuer.append(True)

        self.cascade.continuer_publication = continuer_publication

        self.cascade.trigger_conditionnel_fichiers_completes(params)

        self.assertTrue(calls_continuer[0])

    def test_trigger_conditionnel_fichiers_completes_fuuid_encours(self):
        params = {
            'complete': True,
            'identificateur_document': {'fuuid': 'DUMMY-doc'}
        }

        self.contexte.document_dao.valeurs_aggregate.append([{'en_cours': 1}])

        calls_continuer = list()

        def continuer_publication(*args, **kwargs):
            calls_continuer.append(True)

        self.cascade.continuer_publication = continuer_publication

        self.cascade.trigger_conditionnel_fichiers_completes(params)

        self.assertEqual(0, len(calls_continuer))

    def test_preparer_permission_secret(self):
        secret_chiffre = multibase.encode('base64', b'un secret')

        resultat = self.cascade.preparer_permission_secret(secret_chiffre)

        self.assertEqual(1, len(resultat['liste_hachage_bytes']))
        self.assertEqual('z8VwCDFkrafngguGPikr5pyWe32CiwU8Yqkv6tbBRyuCeHJArkeKLairt3NTHDVTCjmHR5ioMvDkYhHhqNRmyQCP9qX', resultat['liste_hachage_bytes'][0])
        self.assertIsNotNone(secret_chiffre)

    def test_continuer_publication_stop_collectionsfichiers(self):
        self.trigger.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            'sites': [],
        }])

        # self.contexte.document_dao.valeurs_find.append([
        #
        # ])

        self.trigger.compteur_trigger_collections_fichiers = 1

        self.cascade.continuer_publication()

        self.assertEqual(1, len(self.trigger.trigger_traitement_collections_fichiers_calls))
        self.assertEqual(0, len(self.trigger.trigger_publication_fichiers_calls))

    def test_continuer_publication_stop_publication_fichiers(self):
        self.trigger.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            'sites': [],
        }])

        self.trigger.compteur_trigger_collections_fichiers = 0
        self.trigger.compteur_trigger_fichiers = 1

        section_calls = list()

        def continuer_publication_sections(*args, **kwargs):
            section_calls.append(True)
            return 1

        self.cascade.continuer_publication_sections = continuer_publication_sections

        self.cascade.continuer_publication()


        self.assertEqual(1, len(self.trigger.trigger_traitement_collections_fichiers_calls))
        self.assertEqual(1, len(self.trigger.trigger_publication_fichiers_calls))
        self.assertEqual(0, len(section_calls))

    def test_continuer_publication_stop_publication_sections(self):
        self.trigger.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            'sites': [],
        }])

        self.trigger.compteur_trigger_collections_fichiers = 0
        self.trigger.compteur_trigger_fichiers = 0

        section_calls = list()
        configuration_calls = list()

        def continuer_publication_sections(*args, **kwargs):
            section_calls.append(True)
            return 1

        def continuer_publication_configuration(*args, **kwargs):
            configuration_calls.append(True)
            return 1

        self.cascade.continuer_publication_sections = continuer_publication_sections
        self.cascade.continuer_publication_configuration = continuer_publication_configuration

        self.cascade.continuer_publication()

        self.assertEqual(1, len(self.trigger.trigger_traitement_collections_fichiers_calls))
        self.assertEqual(1, len(self.trigger.trigger_publication_fichiers_calls))
        self.assertEqual(1, len(section_calls))
        self.assertEqual(0, len(configuration_calls))

    def test_continuer_publication_stop_publication_siteconfig(self):
        self.trigger.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            'sites': [],
        }])

        self.trigger.compteur_trigger_collections_fichiers = 0
        self.trigger.compteur_trigger_fichiers = 0

        section_calls = list()
        configuration_calls = list()
        publication_webapps = list()

        def continuer_publication_sections(*args, **kwargs):
            section_calls.append(True)
            return 0

        def continuer_publication_configuration(*args, **kwargs):
            configuration_calls.append(True)
            return 1

        def continuer_publication_webapps(*args, **kwargs):
            publication_webapps.append(True)
            return 1

        self.cascade.continuer_publication_sections = continuer_publication_sections
        self.cascade.continuer_publication_configuration = continuer_publication_configuration
        self.cascade.continuer_publication_webapps = continuer_publication_webapps

        self.cascade.continuer_publication()

        self.assertEqual(1, len(self.trigger.trigger_traitement_collections_fichiers_calls))
        self.assertEqual(1, len(self.trigger.trigger_publication_fichiers_calls))
        self.assertEqual(1, len(section_calls))
        self.assertEqual(1, len(configuration_calls))
        self.assertEqual(0, len(publication_webapps))

    def test_continuer_publication_stop_publication_webapps(self):
        self.trigger.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            'sites': [],
        }])

        self.trigger.compteur_trigger_collections_fichiers = 0
        self.trigger.compteur_trigger_fichiers = 0

        section_calls = list()
        configuration_calls = list()
        publication_webapps = list()

        def continuer_publication_sections(*args, **kwargs):
            section_calls.append(True)
            return 0

        def continuer_publication_configuration(*args, **kwargs):
            configuration_calls.append(True)
            return 0

        def continuer_publication_webapps(*args, **kwargs):
            publication_webapps.append(True)
            return 1

        self.cascade.continuer_publication_sections = continuer_publication_sections
        self.cascade.continuer_publication_configuration = continuer_publication_configuration
        self.cascade.continuer_publication_webapps = continuer_publication_webapps

        self.cascade.continuer_publication()

        self.assertEqual(1, len(self.trigger.trigger_traitement_collections_fichiers_calls))
        self.assertEqual(1, len(self.trigger.trigger_publication_fichiers_calls))
        self.assertEqual(1, len(section_calls))
        self.assertEqual(1, len(configuration_calls))
        self.assertEqual(1, len(publication_webapps))

    def test_continuer_publier_uploadfichiers(self):

        liste_res_cdns = []

        # res fichiers
        self.contexte.document_dao.valeurs_find.append([{
            'uuid': 'DUMMY-uuid'
        }])

        calls_processus = list()

        def demarrer_processus(*args, **kwargs):
            calls_processus.append(True)

        self.cascade.demarrer_processus = demarrer_processus

        self.cascade.continuer_publier_uploadfichiers(liste_res_cdns)

        self.assertEqual(1, len(calls_processus))

        pass

    def test_continuer_publication_sections(self):
        self.cascade.triggers_publication.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            'sites': []
        }])

        self.contexte.document_dao.valeurs_find.append([{
            'uuid': 'DUMMY-uuid'
        }])

        self.trigger.compteur_publier_collectionfichiers = 1
        self.trigger.compteur_publier_uploadpages = 1

        compteur = self.cascade.continuer_publication_sections()
        self.assertEqual(0, compteur)

    def test_continuer_publication_sections_1site(self):
        self.cascade.triggers_publication.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            'sites': ['DUMMY-site-1']
        }])

        self.contexte.document_dao.valeurs_find.append([{
            'uuid': 'DUMMY-uuid'
        }])

        self.trigger.compteur_publier_collectionfichiers = 1
        self.trigger.compteur_publier_uploadpages = 1

        compteur = self.cascade.continuer_publication_sections()
        self.assertEqual(2, compteur)

    def test_continuer_publication_configuration(self):
        self.trigger.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn',
            'sites': ['DUMMY-site-1']
        }])

        self.trigger.compteur_publier_configuration = 1
        self.trigger.compteur_publier_mapping = 1

        compteur = self.cascade.continuer_publication_configuration()

        self.assertEqual(2, compteur)

        emettre_publier_configuration_calls = self.trigger.emettre_publier_configuration_calls
        emettre_publier_mapping_calls = self.trigger.emettre_publier_mapping_calls

        self.assertEqual(1, len(emettre_publier_configuration_calls))
        self.assertEqual(1, len(emettre_publier_mapping_calls))

        pass

    def test_continuer_publication_webapps(self):

        # res
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'DUMMY-cdn': False}
        })

        self.cascade.triggers_publication.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn'
        }])

        self.trigger.compteur_publier_webapps = 1

        compteur = self.cascade.continuer_publication_webapps()

        self.assertEqual(1, compteur)
        self.assertEqual(1, len(self.trigger.emettre_publier_webapps_calls))

    def test_continuer_publication_webapps_complete(self):

        # res
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: ['DUMMY-cdn']
        })

        self.cascade.triggers_publication.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn'
        }])

        self.trigger.compteur_publier_webapps = 1

        compteur = self.cascade.continuer_publication_webapps()

        self.assertEqual(0, compteur)
        self.assertEqual(0, len(self.trigger.emettre_publier_webapps_calls))

    def test_continuer_publication_webapps_progres(self):

        # res
        self.contexte.document_dao.valeurs_find.append({
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'DUMMY-cdn': True}
        })

        self.cascade.triggers_publication.sites_par_cdn.append([{
            ConstantesPublication.CHAMP_CDN_ID: 'DUMMY-cdn'
        }])

        self.trigger.compteur_publier_webapps = 1

        compteur = self.cascade.continuer_publication_webapps()

        self.assertEqual(1, compteur)
        self.assertEqual(0, len(self.trigger.emettre_publier_webapps_calls))

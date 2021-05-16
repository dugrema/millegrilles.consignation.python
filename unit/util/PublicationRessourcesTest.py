import json
import logging

from unit.helpers.TestBaseContexte import TestCaseContexte

from millegrilles.util.PublicationRessources import InvalidateurRessources, TriggersPublication
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


class StubCascade:

    def __init__(self, contexte):
        self.__contexte = contexte
        self.demarrer_processus_calls = list()

    @property
    def document_dao(self):
        return self.__contexte.document_dao

    def demarrer_processus(self, *args, **kwargs):
        self.demarrer_processus_calls.append({'args': args, 'kwargs': kwargs})

    def preparer_permission_secretawss3(self, *args, **kwargs):
        return 'PERMISSION DUMMY'


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

    def test_preparer_sitesparcdn(self):
        pass

    def test_trouver_ressources_manquantes(self):
        pass

    def test_demarrer_publication_complete(self):
        pass

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

    def test_trigger_publication_fichiers(self):
        self.trigger.trigger_publication_fichiers()

    def test_trigger_publication_sections(self):
        pass

    def test_trigger_commande_publier_uploadfichiers(self):
        pass


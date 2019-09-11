import logging

from delta import html
from millegrilles.noeuds.Publicateur import ExporterDeltaPlume, PublierCataloguePlume

logging.basicConfig()
logging.getLogger('millegrilles').setLevel(logging.DEBUG)


class TestDelta:

    def __init__(self):
        self.delta_1 = {'ops':
            [
                { "insert":"Quill\nEditor\n\n" },
                { "insert": "bold",
                  "attributes": {"bold": True}},
                { "insert":" and the " },
                { "insert":"italic",
                  "attributes": { "italic": True }},
                { "insert":"\n\nNormal\n" },
            ]
        }

    def render(self, delta):
        resultat = html.render(delta['ops'], pretty=True)
        print(resultat)


class TestExportPlumeHtml:

    def __init__(self):
        self.configuration = {
            'webroot': '/home/mathieu/tmp'
        }

        self.delta_1 = {'ops':
            [
                {"insert": "Quill\nEditor\n\n"},
                {"insert": "bold",
                 "attributes": {"bold": True}},
                {"insert": " and the "},
                {"insert": "italic",
                 "attributes": {"italic": True}},
                {"insert": "\n\nNormal\n"},
            ]
        }

        self.message = {
            'quilldelta': self.delta_1,
            'uuid': 'abcd-1234',
            'titre': 'Un fichier de test, c''est le fun'
        }

        self.exporteur = ExporterDeltaPlume(self.configuration, self.message)

    def exporter(self):
        self.exporteur.exporter_html()


class TestPublierCataloguePlume:

    def __init__(self):
        self.configuration = {
            'webroot': '/home/mathieu/tmp'
        }

        self.doc_catalogue = {
            'documents': [
                {
                    'titre': 'abcd',
                    'uuid': 'abcd-1234',
                    'categories': ['a', 'b'],
                    '_mg-derniere-modification': 1000,
                },
                {
                    'titre': '1234',
                    'uuid': 'abcd-1235',
                    'categories': ['c'],
                    '_mg-derniere-modification': 1001,
                },
                {
                    'titre': 'efgh',
                    'uuid': 'abcd-1236',
                    'categories': [],
                    '_mg-derniere-modification': 1002,
                },
            ]
        }

        self.exportCatalogue = PublierCataloguePlume(self.configuration, self.doc_catalogue)

    def exporter(self):
        self.exportCatalogue.exporter_catalogue()


# ========= MAIN ==========

# test = TestDelta()
# test.render(test.delta_1)

# testExporteur = TestExportPlumeHtml()
# testExporteur.exporter()

testCatalogue = TestPublierCataloguePlume()
testCatalogue.exporter()

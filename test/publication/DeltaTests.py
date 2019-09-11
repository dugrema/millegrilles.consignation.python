import logging

from delta import html
from millegrilles.noeuds.Publicateur import ExporterDeltaPlume

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


# ========= MAIN ==========

# test = TestDelta()
# test.render(test.delta_1)

testExporteur = TestExportPlumeHtml()
testExporteur.exporter()

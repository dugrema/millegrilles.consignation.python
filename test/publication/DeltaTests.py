import logging

from delta import html
from millegrilles.noeuds.Publicateur import ExporterPlume, PublierCataloguePlume, ExporterPageHtml, ConstantesPublicateur, PublierRessourcesStatiques

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
        self.delta_1 = \
            {'ops':
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

        self.exporteur = ExporterPlume(self, self.message)

    @property
    def webroot(self):
        return '/home/mathieu/tmp'

    def exporter(self):
        self.exporteur.exporter_html()


class TestPublierCataloguePlume:

    def __init__(self):
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

        self.exportCatalogue = PublierCataloguePlume(self, self.doc_catalogue)

    @property
    def webroot(self):
        return '/home/mathieu/tmp'

    def exporter(self):
        self.exportCatalogue.exporter_catalogue()


class TestExportAccueilHtml:

    def __init__(self):
        self._exporter = ExporterPageHtml(self, ConstantesPublicateur.PATH_FICHIER_ACCUEIL, 'index.html')
        self._ressources = PublierRessourcesStatiques(self)

    @property
    def template_path(self):
        return '../../html'

    @property
    def webroot(self):
        return '/home/mathieu/tmp'

    @property
    def contexte(self):
        configuration = MicroMock(idmg='local')
        return MicroMock(configuration=configuration)

    def render(self):
        self._exporter.exporter_html()

    def ressources(self):
        self._ressources.copier_ressources()


class MicroMock:

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

# ========= MAIN ==========

# test = TestDelta()
# test.render(test.delta_1)

# testExporteur = TestExportPlumeHtml()
# testExporteur.exporter()

# testCatalogue = TestPublierCataloguePlume()
# testCatalogue.exporter()

testAccueil = TestExportAccueilHtml()
testAccueil.render()
# testAccueil.ressources()

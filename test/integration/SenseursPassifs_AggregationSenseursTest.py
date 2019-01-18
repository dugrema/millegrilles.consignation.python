from millegrilles.domaines.SenseursPassifs import ProducteurDocumentSenseurPassif
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles

import logging


class AggregationSenseursDocumentTest:

    def __init__(self):
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser()

        self.producteur = ProducteurDocumentSenseurPassif(self.contexte)

    def run(self):

        id_document = "5c421f4024fb4ce929dacd8c"

        self.producteur.calculer_aggregation_journee(id_document)
        self.producteur.calculer_aggregation_mois(id_document)


# ---- MAIN ----
logging.basicConfig()
logging.getLogger('millegrilles').setLevel(logging.DEBUG)

test = AggregationSenseursDocumentTest()
test.run()

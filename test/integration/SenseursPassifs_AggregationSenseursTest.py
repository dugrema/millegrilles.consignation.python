from mgdomaines.appareils import ProducteurDocumentSenseurPassif
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.DocumentDAO import MongoDAO


class AggregationSenseursDocumentTest:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()
        print("Connecter Pika")
        self.messageDao = PikaDAO(self.configuration)
        self.messageDao.connecter()
        print("Connection MongDB")
        self.documentDao = MongoDAO(self.configuration)
        self.documentDao.connecter()

        self.producteur = ProducteurDocumentSenseurPassif(self.messageDao, self.documentDao)

    def run(self):

        id_document = "5beedd8482cc2cb5ab0a90e5"

        self.producteur.calculer_aggregation_journee(id_document)
        self.producteur.calculer_aggregation_mois(id_document)

### MAIN ###

test = AggregationSenseursDocumentTest()
test.run()
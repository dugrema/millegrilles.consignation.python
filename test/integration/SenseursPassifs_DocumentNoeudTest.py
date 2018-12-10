from mgdomaines.appareils import ProducteurDocumentNoeud
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.DocumentDAO import MongoDAO


class NoeudSenseursDocumentTest:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()
        print("Connecter Pika")
        self.messageDao = PikaDAO(self.configuration)
        self.messageDao.connecter()
        print("Connection MongDB")
        self.documentDao = MongoDAO(self.configuration)
        self.documentDao.connecter()

        self.producteur = ProducteurDocumentNoeud(self.messageDao, self.documentDao)

    def run(self):

        self.producteur.maj_document_noeud_senseurpassif("5beedd8482cc2cb5ab0a90e5")

### MAIN ###

test = NoeudSenseursDocumentTest()
test.run()
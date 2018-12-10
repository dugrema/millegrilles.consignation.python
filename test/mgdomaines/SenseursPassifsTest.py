import unittest
import datetime
from bson.objectid import ObjectId
from mgdomaines.appareils import ProducteurDocumentSenseurPassif

class SenseursPassifsTest(unittest.TestCase):

    def setUp(self):
        self._document_dao = DocumentDaoStub()
        self._message_dao = MessageDaoStub()

        self.producteur_document_senseur_passif = ProducteurDocumentSenseurPassif(self._message_dao, self._document_dao)

        self.transaction_sample1 = {
            "_id": ObjectId("5bec7292e09409320fc8896f"),
            "charge-utile": {
                "temps_lecture": 1541826019,
                "bat_mv": 3369,
                "pression": 100.6,
                "humidite": 0,
                "noeud": "cuisine.maple.mdugre.info",
                "senseur": 16,
                "temperature": 18.4,
                "location": "Bureau"
            },
            "info-transaction": {
                "source-systeme": "cuisine@cuisine.maple.mdugre.info",
                "signature_contenu": "",
                "uuid-transaction": "9beb5cea-e840-11e8-b40b-00155d011f00",
                "domaine": "mgdomaines.appareils.senseur",
                "estampille": 1541826019
            },
            "evenements": {
                "transaction_nouvelle": [
                    datetime.datetime.strptime("2018-11-10T00:00:19.000Z", "%Y-%m-%dT%H:%M:%S.%fZ")
                ],
                "document_persiste": [
                    datetime.datetime.strptime("2018-11-14T09:08:02.000Z", "%Y-%m-%dT%H:%M:%S.%fZ")
                ]
            }
        }

    def test_sauvegarder_document_update(self):
        self.producteur_document_senseur_passif.maj_document_senseur(self.transaction_sample1)

    def test_sauvegarder_document_upsert(self):
        self._document_dao.get_collection('').matched_count=0
        self.producteur_document_senseur_passif.maj_document_senseur(self.transaction_sample1)

class MessageDaoStub:
    pass


class CollectionStub:

    def __init__(self):
        self.matched_count=1

    def update_one(self, filter, update, upsert=False):
        return ResultatStub(self.matched_count)

class ResultatStub:

    def __init__(self, count=1):
        self.matched_count = count
        self.upserted_id = 1234

class DocumentDaoStub:

    def __init__(self):
        self.collection = CollectionStub()

    def get_collection(self, collection):
        return self.collection

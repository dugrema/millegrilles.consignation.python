from pymongo import MongoClient

import logging
import ssl

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO

class TesterCertificatsMongoDB:

    def __init__(self):
        self._client = None
        self._logger = logging.getLogger('TesterCertificatsMongoDB')
        self._configuration = dict()
        self.configuration = TransactionConfiguration()

        self.mongo_dao = None

    def connecter(self):
        self._client = MongoClient(**self._configuration)

        self._logger.debug("Verify if connection established")
        self._client.admin.command('ismaster')

    def connecter_mongodao(self):
        self.mongo_dao = MongoDAO(self.configuration)
        self._client = self.mongo_dao.connecter()

    def preparer_configuration_interne(self):
        self._configuration['host'] = 'think003.pivoine.mdugre.info'
        self._configuration['port'] = 27017
        self._configuration['username'] = 'root'
        self._configuration['password'] = 'example'
        self._configuration['ssl'] = True
        self._configuration['ssl_cert_reqs'] = ssl.CERT_REQUIRED
        self._configuration['ssl_certfile'] = '/usr/local/etc/millegrilles/certs/keys/millegrilles.pem.key_cert'
        self._configuration['ssl_ca_certs'] = '/usr/local/etc/millegrilles/certs/millegrilles.authority.pem'

    def preparer_configuration_objet(self):
        self.configuration.loadEnvironment()
        self._configuration = self.configuration.format_mongo_config()
        self._logger.info("Configuration Mongo: %s" % str(self._configuration))

    def lire_document(self):
        coll_allo = self.mongo_dao.get_collection('coll_allo')
        # doc = {'key': 'value', 'message': 'Super!'}
        # coll_allo.insert_one(doc)

        doc = coll_allo.find_one(filter={'key': 'value'})
        self._logger.info('Document trouve: %s' % str(doc))


def tester():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('TesterCertificatsMongoDB').setLevel(logging.DEBUG)
    test = TesterCertificatsMongoDB()

    # test.preparer_configuration_interne()
    test.preparer_configuration_objet()

    # test.connecter()
    test.connecter_mongodao()

    test.lire_document()


tester()

from pymongo import MongoClient

import logging
import ssl


class TesterCertificatsMongoDB:

    def __init__(self):
        self._client = None
        self._logger = logging.getLogger('TesterCertificatsMongoDB')

    def connecter(self):
        self._client = MongoClient(
            'think003.pivoine.mdugre.info',
            27017,
            username='root',
            password='example',
            ssl=True,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            ssl_certfile='/home/mathieu/certificates/millegrilles/privkeys/dev1.pem.key_cert',
            ssl_ca_certs='/home/mathieu/certificates/millegrilles/certs/millegrilles_signing_cert.pem.fullchain'
        )

        self._logger.debug("Verify if connection established")
        self._client.admin.command('ismaster')

    def lire_document(self):
        collection_test = self._client.get_collection('test')
        curseur = collection_test.find_one(filter={'key': 'value'})
        for doc in curseur:
            self._logger.info(str(doc))


def tester():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('TesterCertificatsMongoDB').setLevel(logging.DEBUG)
    test = TesterCertificatsMongoDB()
    test.connecter()
    test.lire_document()


tester()

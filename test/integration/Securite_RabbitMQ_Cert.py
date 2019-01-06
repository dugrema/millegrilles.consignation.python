import logging
import pika
import ssl

from pika.credentials import PlainCredentials

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO


class TestCertificatsRabbitMQ:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.connectionmq = None
        self.channel = None

        self.message_dao = None

    def configurer(self):
        self.configuration.loadEnvironment()
        self.message_dao = PikaDAO(self.configuration)

    def preparer_connexion(self):
        connection_parameters = {
            'host': self.configuration.mq_host,
            'port': self.configuration.mq_port,
            'virtual_host': self.configuration.nom_millegrille,
            'heartbeat': 300
        }

        credentials = {
            'username': self.configuration.mq_user,
            'password': self.configuration.mq_password,
            'erase_on_connect': True
        }
        connection_parameters['credentials'] = PlainCredentials(**credentials)

        if self.configuration.mq_ssl == 'on':
            # verify_mode = ssl.CERT_NONE
            # server_hostname = None
            ssl_options = {
                'ssl_version': ssl.PROTOCOL_TLSv1_2,
                'keyfile': '/usr/local/etc/millegrilles/certs/keys/think003.pivoine.mdugre.info.pem',
                'certfile': '/usr/local/etc/millegrilles/certs/think003.pivoine.mdugre.info.cert.pem',
                'ca_certs': '/usr/local/etc/millegrilles/certs/millegrilles.authority.pem',
                'cert_reqs': ssl.CERT_REQUIRED
            }

            connection_parameters['ssl'] = True
            connection_parameters['ssl_options'] = ssl_options

        return connection_parameters

    def connecter_test(self):
        connection_parameters = pika.ConnectionParameters(** self.preparer_connexion())
        self.connectionmq = pika.BlockingConnection(connection_parameters)

    def connecter_dao(self):
        self.connectionmq = self.message_dao.connecter()

    def verifier_connexion(self):
        self.channel = self.connectionmq.channel()
        self.channel.basic_qos(prefetch_count=1)

    def transmettre_message(self):
        pass

    def fermer(self):
        self.connectionmq.close()


def tester():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('TestCertificats_RabbitMQ').setLevel(logging.DEBUG)

    test = TestCertificatsRabbitMQ()
    test.configurer()
    # test.connecter_test()
    test.connecter_dao()
    test.verifier_connexion()
    test.fermer()


tester()

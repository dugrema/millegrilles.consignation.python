import logging
import pika
import ssl

from pika.credentials import PlainCredentials

from millegrilles.dao.Configuration import TransactionConfiguration

class TestCertificatsRabbitMQ:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.connectionmq = None
        self.channel = None

    def configurer(self):
        self.configuration.loadEnvironment()

    def connecter(self):
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

        self.connectionmq = pika.BlockingConnection(pika.ConnectionParameters(**connection_parameters))

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
    test.connecter()
    test.verifier_connexion()
    test.fermer()


tester()

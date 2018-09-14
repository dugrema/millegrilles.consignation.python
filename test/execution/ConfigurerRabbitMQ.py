# Script qui agit comme set-up pour RabbitMQ

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO

configuration = TransactionConfiguration()
configuration.loadEnvironment()

messagedao = PikaDAO(configuration)

messagedao.connecter()
messagedao.configurer_rabbitmq()

messagedao.deconnecter()
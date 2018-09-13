# Script qui agit comme set-up pour RabbitMQ

from millegrilles.transaction.Configuration import TransactionConfiguration
from millegrilles.transaction.MessageDAO import PikaDAO

configuration = TransactionConfiguration()
configuration.loadEnvironment()

messagedao = PikaDAO(configuration)

messagedao.connecter()
messagedao.configurer_rabbitmq()

messagedao.deconnecter()
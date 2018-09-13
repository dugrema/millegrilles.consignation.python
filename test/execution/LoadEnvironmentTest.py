from millegrilles.transaction.Configuration import TransactionConfiguration

configuration = TransactionConfiguration()

# S'assurer d'ajuster la variable d'environnement suivante: MG_MQ_HOST


print("Host avant: %s, Port avant: %s" % (configuration.mq_host, configuration.mq_port))

configuration.loadEnvironment()

print("Host Apres: %s, Port apres: %s" % (configuration.mq_host, configuration.mq_port))
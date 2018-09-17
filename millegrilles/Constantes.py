# Constantes de MilleGrillesPython

# Configuration MQ
CONFIG_MQ_HOST = 'mq_host'
CONFIG_MQ_PORT = 'mq_port'
CONFIG_MQ_EXCHANGE_EVENEMENTS = 'mq_exchange_evenements'
CONFIG_QUEUE_NOUVELLES_TRANSACTIONS = 'mq_queue_nouvelles_transactions'
CONFIG_QUEUE_ENTREE_PROCESSUS = 'mq_queue_entree_processus'
CONFIG_QUEUE_ERREURS_TRANSACTIONS = 'mq_queue_erreurs_transactions'
CONFIG_QUEUE_MGP_PROCESSUS =  'mq_queue_mgp_processus'

DEFAUT_MQ_EXCHANGE_EVENEMENTS = 'millegrilles.evenements'
DEFAUT_QUEUE_NOUVELLES_TRANSACTIONS = 'nouvelles_transactions'
DEFAUT_QUEUE_ENTREE_PROCESSUS = 'entree_processus'
DEFAUT_QUEUE_ERREURS_TRANSACTIONS = 'erreurs_transactions'
DEFAUT_QUEUE_MGP_PROCESSUS = 'mgp_processus'

# Configuration Mongo
CONFIG_MONGO_HOST = 'mongo_host'
CONFIG_MONGO_PORT = 'mongo_port'
CONFIG_MONGO_USER = 'mongo_user'
CONFIG_MONGO_PASSWORD = 'mongo_password'

# Configuration MilleGrilles
CONFIG_NOM_MILLEGRILLE = 'nom_millegrille'

# Valeurs par defaut
DEFAUT_NOM_MILLEGRILLE = 'sansnom'

# Environnement
PREFIXE_ENV_MG = 'MG_'

# Constantes de processus
PROCESSUS_ETAPE_INITIALE = 'initiale'
PROCESSUS_ETAPE_FINALE = 'finale'
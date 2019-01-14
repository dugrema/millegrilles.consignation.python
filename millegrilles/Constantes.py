# Constantes de MilleGrillesPython

CONFIG_FICHIER_JSON = 'mg_config_json'  # Fichier de configuration JSON a combiner avec les autres configurations

# Configuration MQ
CONFIG_MQ_HOST = 'mq_host'
CONFIG_MQ_PORT = 'mq_port'
CONFIG_MQ_VIRTUAL_HOST = 'mq_virtual_host'
CONFIG_MQ_EXCHANGE_EVENEMENTS = 'mq_exchange_evenements'
CONFIG_MQ_USER = 'mq_user'
CONFIG_MQ_PASSWORD = 'mq_password'
CONFIG_MQ_HEARTBEAT = 'mq_heartbeat'
CONFIG_MQ_SSL = 'mq_ssl'
CONFIG_MQ_KEYFILE = 'mq_keyfile'
CONFIG_MQ_CERTFILE = 'mq_certfile'
CONFIG_MQ_CA_CERTS = 'mq_ca_certs'

CONFIG_QUEUE_NOUVELLES_TRANSACTIONS = 'mq_queue_nouvelles_transactions'
CONFIG_QUEUE_ERREURS_TRANSACTIONS = 'mq_queue_erreurs_transactions'
CONFIG_QUEUE_MGP_PROCESSUS = 'mq_queue_mgp_processus'
CONFIG_QUEUE_ERREURS_PROCESSUS = 'mq_queue_erreurs_processus'
CONFIG_QUEUE_GENERATEUR_DOCUMENTS = 'mq_queue_generateur_documents'
CONFIG_QUEUE_NOTIFICATIONS = 'mq_queue_notifications'

DEFAUT_MQ_EXCHANGE_EVENEMENTS = 'millegrilles.evenements'
DEFAUT_MQ_VIRTUAL_HOST = '/'
DEFAUT_MQ_HEARTBEAT = '300'
DEFAUT_QUEUE_NOUVELLES_TRANSACTIONS = 'nouvelles_transactions'
DEFAUT_QUEUE_ERREURS_TRANSACTIONS = 'erreurs_transactions'
DEFAUT_QUEUE_MGP_PROCESSUS = 'mgp_processus'
DEFAUT_QUEUE_ERREURS_PROCESSUS = 'erreurs_processus'
DEFAUT_QUEUE_GENERATEUR_DOCUMENTS = 'generateur_documents'
DEFAUT_QUEUE_NOTIFICATIONS = 'notifications'

DEFAUT_HOSTNAME = 'localhost'
DEFAUT_KEYFILE = '/usr/local/etc/millegrilles/keys/pki.millegrilles.ssl.key'
DEFAUT_KEYCERTFILE = '/usr/local/etc/millegrilles/keys/pki.millegrilles.ssl.key_cert'
DEFAUT_CERTFILE = '/usr/local/etc/millegrilles/certs/pki.millegrilles.ssl.cert'
DEFAUT_CA_CERTS = '/usr/local/etc/millegrilles/certs/pki.millegrilles.ssl.CAchain'

# Configuration Mongo
CONFIG_MONGO_HOST = 'mongo_host'
CONFIG_MONGO_PORT = 'mongo_port'
CONFIG_MONGO_USER = 'mongo_username'
CONFIG_MONGO_PASSWORD = 'mongo_password'
CONFIG_MONGO_SSL = 'mongo_ssl'
CONFIG_MONGO_SSL_CAFILE = 'mongo_ssl_ca_certs'
CONFIG_MONGO_SSL_KEYFILE = 'mongo_ssl_certfile'

MONGO_DOC_ID = '_id'

# Configuration MilleGrilles
CONFIG_NOM_MILLEGRILLE = 'nom_millegrille'

# Domaines
CONFIG_DOMAINES_CONFIGURATION = 'domaines_json'

# Email notifications
CONFIG_EMAIL_HOST = 'email_host'
CONFIG_EMAIL_PORT = 'email_port'
CONFIG_EMAIL_USER = 'email_user'
CONFIG_EMAIL_PASSWORD = 'email_password'
CONFIG_EMAIL_TO = 'email_to'
CONFIG_EMAIL_FROM = 'email_from'

# Valeurs par defaut
DEFAUT_MQ_USER = 'transaction'
DEFAUT_NOM_MILLEGRILLE = 'sansnom'

# Environnement
PREFIXE_ENV_MG = 'MG_'

TRANSACTION_MESSAGE_LIBELLE_SOURCE_SYSTEME = 'source-systeme'
TRANSACTION_MESSAGE_LIBELLE_ID_MONGO = '_id-transaction'
TRANSACTION_MESSAGE_LIBELLE_UUID = 'uuid-transaction'
TRANSACTION_MESSAGE_LIBELLE_EVENEMENT = '_evenements'  # Precedemment evenements (sans underscore)
TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE = 'estampille'
TRANSACTION_MESSAGE_LIBELLE_SIGNATURE = '_signature'
TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION = 'en-tete'  # Precedemment info-transaction
TRANSACTION_MESSAGE_LIBELLE_EN_TETE = 'en-tete'
# TRANSACTION_MESSAGE_LIBELLE_CHARGE_UTILE = 'charge-utile'  # Deprecated
TRANSACTION_MESSAGE_LIBELLE_DOMAINE = 'domaine'
TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT = 'certificat'
TRANSACTION_MESSAGE_LIBELLE_VERSION = 'version'
TRANSACTION_MESSAGE_LIBELLE_VERSION_COURANTE = 3

PROCESSUS_DOCUMENT_LIBELLE_MOTEUR = 'moteur'
PROCESSUS_MESSAGE_LIBELLE_PROCESSUS = 'processus'
PROCESSUS_MESSAGE_LIBELLE_NOMETAPE = 'nom-etape'
PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE = 'etape-suivante'
PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS = '_id_document_processus'
PROCESSUS_MESSAGE_LIBELLE_PARAMETRES = 'parametres'

PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS = PROCESSUS_MESSAGE_LIBELLE_PROCESSUS
PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE = PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE
PROCESSUS_DOCUMENT_LIBELLE_ETAPES = 'etapes'
PROCESSUS_DOCUMENT_LIBELLE_NOMETAPE = 'nom-etape'
PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES = PROCESSUS_MESSAGE_LIBELLE_PARAMETRES
PROCESSUS_DOCUMENT_LIBELLE_DATEEXECUTION = 'date'

# Documents
DOCUMENT_COLLECTION_TRANSACTIONS = 'transactions'
DOCUMENT_COLLECTION_PROCESSUS = 'processus'
DOCUMENT_COLLECTION_INFORMATION_DOCUMENTS = 'information-documents'
DOCUMENT_COLLECTION_INFORMATION_GENEREE = 'information-generee'

# DOCUMENT_INFODOC_CHEMIN = '_mg-chemin'
# DOCUMENT_INFODOC_UUID = '_mg-uuid-doc'
DOCUMENT_INFODOC_LIBELLE = '_mg-libelle'
DOCUMENT_INFODOC_DERNIERE_MODIFICATION = '_mg-derniere-modification'
DOCUMENT_INFODOC_DATE_CREATION = '_mg-creation'

# Evenements
EVENEMENT_MESSAGE_EVENEMENT = 'evenement'
EVENEMENT_TRANSACTION_NOUVELLE = 'transaction_nouvelle'
EVENEMENT_TRANSACTION_ESTAMPILLE = 'estampille'
EVENEMENT_TRANSACTION_TRAITEE = 'transaction_traitee'
EVENEMENT_TRANSACTION_PERSISTEE = 'transaction_persistee'
EVENEMENT_DOCUMENT_PERSISTE = 'document_persiste'
EVENEMENT_DOCUMENT_MAJ = 'document_maj'
EVENEMENT_DOCUMENT_SUPPRIME = 'document_supprime'
EVENEMENT_DOCUMENT_AJOUTE = 'document_ajoute'
EVENEMENT_CEDULEUR = 'ceduleur'
EVENEMENT_NOTIFICATION = 'notification'

DOCUMENT_NOTIFICATION_REGLESIMPLE = 'regle_simple'

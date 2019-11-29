# Constantes de MilleGrillesPython

LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'

CONFIG_FICHIER_JSON = 'mg_config_json'  # Fichier de configuration JSON a combiner avec les autres configurations

# Configuration MQ
CONFIG_MQ_HOST = 'mq_host'
CONFIG_MQ_PORT = 'mq_port'
CONFIG_MQ_VIRTUAL_HOST = 'mq_virtual_host'
# CONFIG_MQ_EXCHANGE_EVENEMENTS = 'mq_exchange_evenements'
CONFIG_MQ_EXCHANGE_MIDDLEWARE = 'mq_exchange_middleware'
CONFIG_MQ_EXCHANGE_INTER = 'mq_exchange_inter'
CONFIG_MQ_EXCHANGE_NOEUDS = 'mq_exchange_noeuds'
CONFIG_MQ_EXCHANGE_PUBLIC = 'mq_exchange_public'
CONFIG_MQ_USER = 'mq_user'
CONFIG_MQ_PASSWORD = 'mq_password'
CONFIG_MQ_HEARTBEAT = 'mq_heartbeat'
CONFIG_MQ_SSL = 'mq_ssl'
CONFIG_MQ_AUTH_CERT = 'mq_auth_cert'
CONFIG_MQ_KEYFILE = 'mq_keyfile'
CONFIG_MQ_CERTFILE = 'mq_certfile'
CONFIG_MQ_CA_CERTS = 'mq_ca_certs'

CONFIG_QUEUE_NOUVELLES_TRANSACTIONS = 'mq_queue_nouvelles_transactions'
CONFIG_QUEUE_EVENEMENTS_TRANSACTIONS = 'mq_queue_evenements_transactions'
CONFIG_QUEUE_ERREURS_TRANSACTIONS = 'mq_queue_erreurs_transactions'
CONFIG_QUEUE_MGP_PROCESSUS = 'mq_queue_mgp_processus'
CONFIG_QUEUE_ERREURS_PROCESSUS = 'mq_queue_erreurs_processus'
CONFIG_QUEUE_GENERATEUR_DOCUMENTS = 'mq_queue_generateur_documents'
CONFIG_QUEUE_NOTIFICATIONS = 'mq_queue_notifications'

# DEFAUT_MQ_EXCHANGE_EVENEMENTS = 'millegrilles.evenements'
DEFAUT_MQ_EXCHANGE_MIDDLEWARE = 'millegrilles.middleware'
DEFAUT_MQ_EXCHANGE_INTER = 'millegrilles.inter'
DEFAUT_MQ_EXCHANGE_NOEUDS = 'millegrilles.noeuds'
DEFAUT_MQ_EXCHANGE_PUBLIC = 'millegrilles.public'
DEFAUT_MQ_VIRTUAL_HOST = '/'
DEFAUT_MQ_HEARTBEAT = '120'
DEFAUT_QUEUE_NOUVELLES_TRANSACTIONS = 'transactions.nouvelles'
DEFAUT_QUEUE_EVENEMENTS_TRANSACTIONS = 'transactions.evenements'
DEFAUT_QUEUE_ERREURS_TRANSACTIONS = 'erreurs_transactions'
DEFAUT_QUEUE_ENTRETIEN_TRANSACTIONS = 'transactions.entretien'
DEFAUT_QUEUE_MGP_PROCESSUS = 'mgp_processus'
DEFAUT_QUEUE_ERREURS_PROCESSUS = 'processus.erreurs'
DEFAUT_QUEUE_GENERATEUR_DOCUMENTS = 'generateur_documents'
DEFAUT_QUEUE_NOTIFICATIONS = 'notifications'

DEFAUT_HOSTNAME = 'localhost'
DEFAUT_KEYFILE = '/usr/local/etc/millegrilles/keys/pki.millegrilles.ssl.key'
DEFAUT_KEYCERTFILE = '/usr/local/etc/millegrilles/keys/pki.millegrilles.ssl.key_cert'
DEFAUT_CERTFILE = '/usr/local/etc/millegrilles/certs/pki.millegrilles.ssl.cert'
DEFAUT_CA_CERTS = '/opt/millegrilles/etc/millegrilles.RootCA.pem'

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
LIBVAL_CONFIGURATION = 'configuration'

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

# PKI
CONFIG_PKI_WORKDIR = 'pki_workdir'
CONFIG_MAITREDESCLES_DIR = 'maitredescles_dir'
CONFIG_PKI_SECRET_DIR = 'pki_secrets'
CONFIG_CA_PASSWORDS = 'pki_ca_passwords'
CONFIG_PKI_CERT_MILLEGRILLE = 'pki_cert_millegrille'
CONFIG_PKI_KEY_MILLEGRILLE = 'pki_key_millegrille'
CONFIG_PKI_PASSWORD_MILLEGRILLE = 'pki_password_millegrille'
CONFIG_PKI_CERT_AUTORITE = 'pki_cert_autorite'
CONFIG_PKI_KEY_AUTORITE = 'pki_key_autorite'
CONFIG_PKI_PASSWORD_AUTORITE = 'pki_password_millegrille'
CONFIG_PKI_CERT_MAITREDESCLES = 'pki_cert_maitredescles'
CONFIG_PKI_KEY_MAITREDESCLES = 'pki_key_maitredescles'
CONFIG_PKI_PASSWORD_MAITREDESCLES = 'pki_password_maitredescles'

DEFAUT_PKI_WORKDIR = '/opt/millegrilles/dist/secure/pki'
DEFAUT_MAITREDESCLES_DIR = '/opt/millegrilles/dist/secure/maitredescles'
DEFAUT_PKI_SECRET_DIR = '/run/secrets'
DEFAULT_CA_PASSWORDS = 'pki.ca.passwords'
DEFAUT_PKI_CERT_MILLEGRILLE = 'pki.ca.millegrille.cert'
DEFAUT_PKI_KEY_MILLEGRILLE = 'pki.ca.millegrille.key'
DEFAUT_PKI_PASSWORD_MILLEGRILLE = 'pki.ca.millegrille.password.txt'
DEFAUT_PKI_CERT_AUTORITE = 'pki.ca.autorite.cert.pem'
DEFAUT_PKI_KEY_AUTORITE = 'pki.ca.autorite.key.pem'
DEFAUT_PKI_PASSWORD_AUTORITE = 'pki.ca.autorite.password.txt'
DEFAUT_PKI_CERT_MAITREDESCLES = 'pki.ca.maitredescles.cert.pem'
DEFAUT_PKI_KEY_MAITREDESCLES = 'pki.ca.maitredescles.key.pem'
DEFAUT_PKI_PASSWORD_MAITREDESCLES = 'pki.ca.maitredescles.password.txt'

# Environnement
PREFIXE_ENV_MG = 'MG_'

TRANSACTION_MESSAGE_LIBELLE_SOURCE_SYSTEME = 'source-systeme'
TRANSACTION_MESSAGE_LIBELLE_ID_MONGO = '_id-transaction'
TRANSACTION_MESSAGE_LIBELLE_UUID = 'uuid-transaction'
TRANSACTION_MESSAGE_LIBELLE_EVENEMENT = '_evenements'  # Precedemment evenements (sans underscore)
TRANSACTION_MESSAGE_LIBELLE_ORIGINE = '_origine'
TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE = 'estampille'
TRANSACTION_MESSAGE_LIBELLE_SIGNATURE = '_signature'
TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION = 'en-tete'  # Precedemment info-transaction
TRANSACTION_MESSAGE_LIBELLE_EN_TETE = 'en-tete'
# TRANSACTION_MESSAGE_LIBELLE_CHARGE_UTILE = 'charge-utile'  # Deprecated
TRANSACTION_MESSAGE_LIBELLE_DOMAINE = 'domaine'
TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT = 'certificat'
TRANSACTION_MESSAGE_LIBELLE_HACHAGE = 'hachage-contenu'
TRANSACTION_MESSAGE_LIBELLE_VERSION = 'version'
TRANSACTION_MESSAGE_LIBELLE_VERSION_4 = 4
TRANSACTION_MESSAGE_LIBELLE_VERSION_COURANTE = TRANSACTION_MESSAGE_LIBELLE_VERSION_4
TRANSACTION_MESSAGE_LIBELLE_PROPERTIES_MQ = 'properties'

TRANSACTION_ROUTING_NOUVELLE = 'transaction.nouvelle'
TRANSACTION_ROUTING_EVENEMENT = 'transaction.evenement'
TRANSACTION_ROUTING_DOCINITIAL = 'docInitial'
TRANSACTION_ROUTING_UPDATE_DOC = 'updateDoc'
PROCESSUS_DOCUMENT_LIBELLE_MOTEUR = 'moteur'
PROCESSUS_MESSAGE_LIBELLE_PROCESSUS = 'processus'
PROCESSUS_MESSAGE_LIBELLE_NOMETAPE = 'nom-etape'
PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE = 'etape-suivante'
PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS = '_id_document_processus'
PROCESSUS_MESSAGE_LIBELLE_PARAMETRES = 'parametres'
PROCESSUS_MESSAGE_LIBELLE_COLLECTION_DONNEES = 'collection_donnees'

PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS_DECLENCHEUR = '_id_document_processus_declencheur'
PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS_ATTENTE = '_id_document_processus_attente'
PROCESSUS_MESSAGE_LIBELLE_RESUMER_TOKENS = 'resumer_tokens'

PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS = PROCESSUS_MESSAGE_LIBELLE_PROCESSUS
PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE = PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE
PROCESSUS_DOCUMENT_LIBELLE_ETAPES = 'etapes'
PROCESSUS_DOCUMENT_LIBELLE_NOMETAPE = 'nom-etape'
PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES = PROCESSUS_MESSAGE_LIBELLE_PARAMETRES
PROCESSUS_DOCUMENT_LIBELLE_DATEEXECUTION = 'date'
PROCESSUS_DOCUMENT_LIBELLE_TOKENS = 'tokens'
PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE = 'attente_token'
PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER = 'resumer_token'
PROCESSUS_DOCUMENT_LIBELLE_TOKEN_CONNECTES = 'connecte_token'
PROCESSUS_DOCUMENT_LIBELLE_RESUMER_COMPTEUR = 'resumer_compteur'
PROCESSUS_DOCUMENT_LIBELLE_INFO = 'info'

# Documents (collections)
DOCUMENT_COLLECTION_TRANSACTIONS = 'transactions'
DOCUMENT_COLLECTION_PROCESSUS = 'processus'
DOCUMENT_COLLECTION_INFORMATION_DOCUMENTS = 'information-documents'
DOCUMENT_COLLECTION_INFORMATION_GENEREE = 'information-generee'

# Collections
COLLECTION_TRANSACTION_STAGING = 'transactions.staging'

# DOCUMENT_INFODOC_CHEMIN = '_mg-chemin'
# DOCUMENT_INFODOC_UUID = '_mg-uuid-doc'
DOCUMENT_INFODOC_LIBELLE = '_mg-libelle'
DOCUMENT_INFODOC_DERNIERE_MODIFICATION = '_mg-derniere-modification'
DOCUMENT_INFODOC_DATE_CREATION = '_mg-creation'
DOCUMENT_INFODOC_SOUSDOCUMENT = 'document'

# Section cryptee d'un document
DOCUMENT_SECTION_CRYPTE = 'crypte'

# Evenements
EVENEMENT_MESSAGE_EVENEMENT = 'evenement'
EVENEMENT_TRANSACTION_NOUVELLE = 'transaction_nouvelle'
EVENEMENT_TRANSACTION_ESTAMPILLE = '_estampille'
EVENEMENT_TRANSACTION_COMPLETE = 'transaction_complete'
EVENEMENT_TRANSACTION_TRAITEE = 'transaction_traitee'
EVENEMENT_TRANSACTION_PERSISTEE = 'transaction_persistee'
EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT = 'erreur_traitement'
EVENEMENT_TRANSACTION_ERREUR_EXPIREE = 'erreur_expiree'
EVENEMENT_DOCUMENT_PERSISTE = 'document_persiste'
EVENEMENT_SIGNATURE_VERIFIEE = 'signature_verifiee'
EVENEMENT_DOCUMENT_MAJ = 'document_maj'
EVENEMENT_DOCUMENT_SUPPRIME = 'document_supprime'
EVENEMENT_DOCUMENT_AJOUTE = 'document_ajoute'
EVENEMENT_CEDULEUR = 'ceduleur'
EVENEMENT_NOTIFICATION = 'notification'
EVENEMENT_RESUMER = 'resumer'
EVENEMENT_PKI = 'pki'

DOCUMENT_TACHE_NOTIFICATION = 'tache_notification'

SECURITE_PUBLIC = '1.public'    # Niveau 1, le moins securitaire. Accessible a n'importe qui.
SECURITE_PRIVE = '2.prive'      # Niveau 2, accessible aux personnes authentifiees
SECURITE_PROTEGE = '3.protege'  # Niveau 3, accessible aux personnes autorisees (delegues, autorise individuellement)
SECURITE_SECURE = '4.secure'    # Niveau 4, accessible uniquement a l'usager et aux delegues directs

SECURITE_LIBELLE_REPONSE = 'acces'
SECURITE_ACCES_REFUSE = '0.refuse'
SECURITE_ACCES_PERMIS = '1.permis'

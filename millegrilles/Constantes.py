# Constantes de MilleGrillesPython
import datetime

LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'

CONFIG_FICHIER_JSON = 'mg_config_json'  # Fichier de configuration JSON a combiner avec les autres configurations

# Configuration MQ
CONFIG_MQ_HOST = 'mq_host'
CONFIG_MQ_PORT = 'mq_port'
CONFIG_MQ_VIRTUAL_HOST = 'mq_virtual_host'
# CONFIG_MQ_EXCHANGE_EVENEMENTS = 'mq_exchange_evenements'
CONFIG_MQ_EXCHANGE_MIDDLEWARE = 'mq_exchange_middleware'
CONFIG_MQ_EXCHANGE_PRIVE = 'mq_exchange_prive'
CONFIG_MQ_EXCHANGE_NOEUDS = 'mq_exchange_noeuds'
CONFIG_MQ_EXCHANGE_PUBLIC = 'mq_exchange_public'
CONFIG_MQ_EXCHANGE_DEFAUT = 'mq_exchange_defaut'
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

CONFIG_BACKUP_WORKDIR = 'backup_workdir'

# DEFAUT_MQ_EXCHANGE_EVENEMENTS = 'millegrilles.evenements'
DEFAUT_MQ_EXCHANGE_MIDDLEWARE = '4.secure'
DEFAUT_MQ_EXCHANGE_NOEUDS = '3.protege'
DEFAUT_MQ_EXCHANGE_PRIVE = '2.prive'
DEFAUT_MQ_EXCHANGE_PUBLIC = '1.public'
DEFAUT_MQ_VIRTUAL_HOST = '/'
DEFAUT_MQ_HEARTBEAT = '30'
DEFAUT_QUEUE_NOUVELLES_TRANSACTIONS = 'transactions.nouvelles'
DEFAUT_QUEUE_EVENEMENTS_TRANSACTIONS = 'transactions.evenements'
DEFAUT_QUEUE_ERREURS_TRANSACTIONS = 'erreurs_transactions'
DEFAUT_QUEUE_ENTRETIEN_TRANSACTIONS = 'transactions.entretien'
DEFAUT_QUEUE_MGP_PROCESSUS = 'mgp_processus'
DEFAUT_QUEUE_ERREURS_PROCESSUS = 'erreurs'
DEFAUT_QUEUE_GENERATEUR_DOCUMENTS = 'generateur_documents'
DEFAUT_QUEUE_NOTIFICATIONS = 'notifications'

DEFAUT_HOSTNAME = 'mq'
DEFAUT_HOSTNAME_MONGO = 'mongo'
DEFAUT_KEYFILE = '/usr/local/etc/millegrilles/keys/pki.millegrilles.ssl.key'
DEFAUT_KEYCERTFILE = '/usr/local/etc/millegrilles/keys/pki.millegrilles.ssl.key_cert'
DEFAUT_CERTFILE = '/usr/local/etc/millegrilles/certs/pki.millegrilles.ssl.cert'
DEFAUT_CA_CERTS = '/opt/millegrilles/etc/millegrilles.RootCA.pem'
DEFAUT_VAR_MILLEGRILLES = '/var/opt/millegrilles'

DEFAUT_CONSIGNATIONFICHIERS_HOST = 'fichiers'
DEFAUT_CONSIGNATIONFICHIERS_PORT = '443'

DEFAUT_BACKUP_WORKDIR = '/tmp/mgbackup'

# Configuration Mongo
CONFIG_MONGO_HOST = 'mongo_host'
CONFIG_MONGO_PORT = 'mongo_port'
CONFIG_MONGO_USER = 'mongo_username'
CONFIG_MONGO_PASSWORD = 'mongo_password'
CONFIG_MONGO_SSL = 'mongo_ssl'
CONFIG_MONGO_SSL_CAFILE = 'mongo_ssl_ca_certs'
CONFIG_MONGO_SSL_CERTFILE = 'mongo_ssl_certfile'
CONFIG_MONGO_SSL_KEYFILE = 'mongo_ssl_keyfile'
CONFIG_MONGO_AUTHSOURCE = 'mongo_authsource'

MONGO_DOC_ID = '_id'

# Configuration MilleGrilles
CONFIG_IDMG = 'idmg'
CONFIG_NOEUD_ID = 'noeud_id'

# Domaines
CONFIG_DOMAINES_CONFIGURATION = 'domaines_json'
CONFIG_DOMAINES_DYNAMIQUES = 'domaines_dynamiques'
LIBVAL_CONFIGURATION = 'configuration'

# Email notifications
CONFIG_EMAIL_HOST = 'email_host'
CONFIG_EMAIL_PORT = 'email_port'
CONFIG_EMAIL_USER = 'email_user'
CONFIG_EMAIL_PASSWORD = 'email_password'
CONFIG_EMAIL_TO = 'email_to'
CONFIG_EMAIL_FROM = 'email_from'

# Serveurs et liens externes
CONFIG_SERVEUR_CONSIGNATIONFICHIERS_HOST = 'consignationfichiers_host'
CONFIG_SERVEUR_CONSIGNATIONFICHIERS_PORT = 'consignationfichiers_port'

# Valeurs par defaut
DEFAUT_MQ_USER = 'transaction'
DEFAUT_IDMG = 'sansnom'

# PKI
CONFIG_PKI_WORKDIR = 'pki_workdir'
CONFIG_MAITREDESCLES_DIR = 'maitredescles_dir'
CONFIG_PKI_SECRET_DIR = 'pki_secrets'
CONFIG_CA_PASSWORDS = 'pki_ca_passwords'
CONFIG_PKI_CERTFILE = 'pki_certfile'
CONFIG_PKI_KEYFILE = 'pki_keyfile'
CONFIG_PKI_CERT_INTERMEDIAIRE = 'pki_cert_intermediaire'
CONFIG_PKI_KEY_INTERMEDIAIRE = 'pki_key_intermediaire'
CONFIG_PKI_PASSWORD_INTERMEDIAIRE = 'pki_password_intermediaire'
CONFIG_PKI_CLECERT_INTERMEDIAIRE = 'pki_clecert_intermediaire'
CONFIG_PKI_CERT_MILLEGRILLE = 'pki_cert_millegrille'
CONFIG_PKI_KEY_MILLEGRILLE = 'pki_key_millegrille'
CONFIG_PKI_PASSWORD_MILLEGRILLE = 'pki_password_millegrille'
CONFIG_PKI_CERT_MAITREDESCLES = 'pki_cert_maitredescles'
CONFIG_PKI_KEY_MAITREDESCLES = 'pki_key_maitredescles'
CONFIG_PKI_PASSWORD_MAITREDESCLES = 'pki_password_maitredescles'

DEFAUT_PKI_WORKDIR = '/tmp'
DEFAUT_MAITREDESCLES_DIR = '/opt/millegrilles/dist/secure/maitredescles'
DEFAUT_PKI_SECRET_DIR = '/run/secrets'
DEFAULT_CA_PASSWORDS = 'pki.ca.passwords'
DEFAUT_PKI_CERT_INTERMEDIAIRE = 'intermediaire.cert.pem'
DEFAUT_PKI_KEY_INTERMEDIAIRE = 'intermediaire.key.pem'
DEFAUT_PKI_PASSWORD_INTERMEDIAIRE = 'intermediaire.passwd.txt'
DEFAUT_PKI_CERT_MILLEGRILLE = 'millegrille.cert.pem'
DEFAUT_PKI_KEY_MILLEGRILLE = 'millegrille.key.pem'
DEFAUT_PKI_PASSWORD_MILLEGRILLE = 'millegrille.passwd.txt'
DEFAUT_PKI_CERT_MAITREDESCLES = 'maitredescles.cert.pem'
DEFAUT_PKI_KEY_MAITREDESCLES = 'maitredescles.key.pem'
DEFAUT_PKI_PASSWORD_MAITREDESCLES = 'maitredescles.passwd.txt'

# Environnement
PREFIXE_ENV_MG = 'MG_'

TRANSACTION_MESSAGE_LIBELLE_IDMG = CONFIG_IDMG
TRANSACTION_MESSAGE_LIBELLE_IDMG_DESTINATION = 'destination'
# TRANSACTION_MESSAGE_LIBELLE_SOURCE_SYSTEME = 'source-systeme'   # Remplace par idmg
TRANSACTION_MESSAGE_LIBELLE_ID_MONGO = '_id-transaction'
TRANSACTION_MESSAGE_LIBELLE_UUID = 'uuid_transaction'
TRANSACTION_MESSAGE_LIBELLE_EVENEMENT = '_evenements'  # Precedemment evenements (sans underscore)
TRANSACTION_MESSAGE_LIBELLE_ORIGINE = '_akid'
TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE = 'estampille'
TRANSACTION_MESSAGE_LIBELLE_SIGNATURE = '_signature'
TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS = '_certificat'
TRANSACTION_MESSAGE_LIBELLE_CONTRESIGNATURES = '_contresignatures'
TRANSACTION_MESSAGE_LIBELLE_CONTRESIGNATURE = 'signature'
TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION = 'en-tete'  # Precedemment info-transaction
TRANSACTION_MESSAGE_LIBELLE_EN_TETE = 'en-tete'
# TRANSACTION_MESSAGE_LIBELLE_CHARGE_UTILE = 'charge-utile'  # Deprecated
TRANSACTION_MESSAGE_LIBELLE_DOMAINE = 'domaine'
TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT = 'certificat'
TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT = 'fingerprint_certificat'
TRANSACTION_MESSAGE_LIBELLE_HACHAGE = 'hachage_contenu'
TRANSACTION_MESSAGE_LIBELLE_VERSION = 'version'
TRANSACTION_MESSAGE_LIBELLE_VERSION_6 = 6
TRANSACTION_MESSAGE_LIBELLE_VERSION_COURANTE = TRANSACTION_MESSAGE_LIBELLE_VERSION_6
TRANSACTION_MESSAGE_LIBELLE_PROPERTIES_MQ = 'properties'
TRANSACTION_MESSAGE_LIBELLE_RESOUMISSIONS = 'resoumissions'

TRANSACTION_ROUTING_NOUVELLE = 'transaction.*.#.*'
TRANSACTION_ROUTING_EVENEMENT = 'evenement.*.#.transactionEvenement'
TRANSACTION_ROUTING_EVENEMENTTOKEN = 'evenement.*.#.transactionToken'
TRANSACTION_ROUTING_EVENEMENTRESET = 'commande.*.#.transactionReset'
TRANSACTION_ROUTING_RESTAURER = 'commande.*.#.restaurerTransaction'
TRANSACTION_ROUTING_RESTAURER_COMMUN = 'commande.transaction.restaurerTransaction'
TRANSACTION_ROUTING_MARQUER_FIN = 'commande.transaction.marquerFin'
TRANSACTION_ROUTING_DOCINITIAL = 'docInitial'
TRANSACTION_ROUTING_UPDATE_DOC = 'updateDoc'
TRANSACTION_ROUTING_ERREURS = 'erreur'

EVENEMENT_ROUTING_PRESENCE_DOMAINES = 'evenement.presence.domaine'

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
DOCUMENT_INFODOC_SECURITE = 'securite'

# Section cryptee d'un document
DOCUMENT_SECTION_CRYPTE = 'crypte'

# Evenements
EVENEMENT_MESSAGE_EVENEMENT = 'evenement'
EVENEMENT_MESSAGE_EVENEMENT_TOKEN = 'evenement_token'
EVENEMENT_MESSAGE_TYPE_TOKEN = 'type_token'
EVENEMENT_MESSAGE_TOKEN = 'token'
EVENEMENT_MESSAGE_EVENEMENTS = 'evenements'
EVENEMENT_MESSAGE_UNSET = 'unset'
EVENEMENT_MESSAGE_EVENEMENT_TIMESTAMP = 'timestamp'
EVENEMENT_TRANSACTION_NOUVELLE = 'transaction_nouvelle'
EVENEMENT_TRANSACTION_ESTAMPILLE = '_estampille'
EVENEMENT_TRANSACTION_COMPLETE = 'transaction_complete'
EVENEMENT_TRANSACTION_TRAITEE = 'transaction_traitee'
EVENEMENT_TRANSACTION_PERSISTEE = 'transaction_persistee'
EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT = 'erreur_traitement'
EVENEMENT_TRANSACTION_ERREUR_EXPIREE = 'erreur_expiree'
EVENEMENT_TRANSACTION_ERREUR_RESOUMISSION = 'erreur_resoumission'
EVENEMENT_TRANSACTION_BACKUP_FLAG = 'backup_flag'
EVENEMENT_TRANSACTION_BACKUP_HORAIRE_COMPLETE = 'backup_horaire'
EVENEMENT_TRANSACTION_BACKUP_ERREUR = 'backup_erreur'
EVENEMENT_TRANSACTION_BACKUP_RESTAURE = 'transaction_restauree'
EVENEMENT_DOCUMENT_PERSISTE = 'document_persiste'
EVENEMENT_SIGNATURE_VERIFIEE = 'signature_verifiee'
EVENEMENT_TRANSACTION_DATE_RESOUMISE = 'resoumise'
EVENEMENT_TRANSACTION_COMPTE_RESOUMISE = 'compte_resoumise'
EVENEMENT_DOCUMENT_MAJ = 'document_maj'
EVENEMENT_DOCUMENT_SUPPRIME = 'document_supprime'
EVENEMENT_DOCUMENT_AJOUTE = 'document_ajoute'
EVENEMENT_CEDULEUR = 'ceduleur'
EVENEMENT_NOTIFICATION = 'notification'
EVENEMENT_RESUMER = 'resumer'
EVENEMENT_REPONSE = 'reponse'
EVENEMENT_VERIFIER_RESUMER = 'verifier.resumer'
EVENEMENT_PKI = 'pki'

EVENEMENT_TOKEN_ATTENTE = 'attente'
EVENEMENT_TOKEN_RESUMER = 'resumer'
EVENEMENT_TOKEN_CONNECTE = 'connecte'

DOCUMENT_TACHE_NOTIFICATION = 'tache_notification'

SECURITE_OUVERT = '0.installation'  # Non configure, le noeud est ouvert et pret a etre initialise
SECURITE_PUBLIC = '1.public'    # Niveau 1, le moins securitaire. Accessible a n'importe qui.
SECURITE_PRIVE = '2.prive'      # Niveau 2, accessible aux personnes authentifiees
SECURITE_PROTEGE = '3.protege'  # Niveau 3, accessible aux personnes autorisees (delegues, autorise individuellement)
SECURITE_SECURE = '4.secure'    # Niveau 4, accessible uniquement a l'usager et aux delegues directs

SECURITE_LIBELLE_REPONSE = 'acces'
SECURITE_ACCES_REFUSE = '0.refuse'
SECURITE_ACCES_PERMIS = '1.permis'
SECURITE_ACCES_ERREUR = '2.erreur'
SECURITE_ACCES_CLE_INDECHIFFRABLE = '3.indechiffrable'
SECURITE_ACCES_CLE_INCONNUE = '4.inconnue'

CLE_CERT_CA = 'pki.millegrille'


class ConstantesSecurite:

    EXCHANGE_SECURE = 'millegrilles.middleware'
    EXCHANGE_PROTEGE = 'millegrilles.noeuds'
    EXCHANGE_PRIVE = 'millegrilles.prive'
    EXCHANGE_PUBLIC = 'millegrilles.public'


class ConstantesDomaines:

    COMMANDE_REGENERER = 'regenerer'
    COMMANDE_GLOBAL_REGENERER = 'commande.global.regenerer'
    COMMANDE_BACKUP = 'backup'
    COMMANDE_DOMAINE_DEMARRER = 'demarrer'
    COMMANDE_DOMAINE_ARRETER = 'arreter'

    REQUETE_GLOBAL_PREFIX = 'requete.ALL'
    REQUETE_STATS_TRANSACTIONS = 'requeteStatsTransactions'


class ConstantesPrincipale:
    """ Constantes pour le domaine de l'interface principale """

    DOMAINE_NOM = 'Principale'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_ROUTING_CHANGEMENTS = 'evenement.%s.document' % DOMAINE_NOM

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_PROFIL_USAGER = 'profil.usager'
    LIBVAL_PROFIL_MILLEGRILLE = 'profil.millegrille'
    LIBVAL_ALERTES = 'alertes'
    LIBVAL_DOMAINES = 'domaines'
    LIBVAL_CLES = 'cles'

    LIBELLE_NOM = 'nom'
    LIBELLE_PRENOM = 'prenom'
    LIBELLE_COURRIEL = 'courriel'
    LIBELLE_TWITTER = 'twitter'
    LIBELLE_FACEBOOK = 'facebook'
    LIBELLE_NOM_MILLEGRILLE = 'nomMilleGrille'
    LIBELLE_NOM_MILLEGRILLE_PAR_LANGUE = 'nomMilleGrilleParLangue'
    LIBELLE_LANGUE_PRINCIPALE = 'langue'
    LIBELLE_LANGUES_ADDITIONNELLES = 'languesAdditionnelles'
    LIBELLE_DOMAINES = 'domaines'
    LIBELLE_MENU = 'menu'

    TRANSACTION_ACTION_FERMERALERTE = '%s.fermerAlerte' % DOMAINE_NOM
    TRANSACTION_ACTION_CREERALERTE = '%s.creerAlerte' % DOMAINE_NOM
    TRANSACTION_ACTION_CREEREMPREINTE = '%s.creerEmpreinte' % DOMAINE_NOM
    TRANSACTION_ACTION_AJOUTER_TOKEN = '%s.ajouterToken' % DOMAINE_NOM
    TRANSACTION_ACTION_MAJ_PROFILUSAGER = '%s.majProfilUsager' % DOMAINE_NOM
    TRANSACTION_ACTION_MAJ_PROFILMILLEGRILLE = '%s.majProfilMilleGrille' % DOMAINE_NOM
    TRANSACTION_MAJ_MENU = '%s.majMenu' % DOMAINE_NOM

    REQUETE_AUTHINFO_MILLEGRILLE = 'getAuthInfo'
    REQUETE_PROFIL_MILLEGRILLE = 'getProfilMillegrille'
    REQUETE_PROFIL_USAGER = 'getProfilUsager'

    DOCUMENT_ALERTES = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_ALERTES,
        'alertes': [
            {'message': "Interface principale initialisee", 'ts': int(datetime.datetime.utcnow().timestamp()*1000)}
        ]
    }

    DOCUMENT_CLES = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CLES,
        'cles': [],
        'challenge_authentification': None,
        'empreinte_absente': True,
    }

    DOCUMENT_DOMAINES = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_DOMAINES,
        LIBVAL_DOMAINES: {
            'SenseursPassifs': {
                'rang': 5,
                'description': 'SenseursPassifs'
            },
            'GrosFichiers': {
                'rang': 3,
                'description': 'GrosFichiers'
            },
            'Principale': {
                'rang': 1,
                'description': 'Principale'
            },
            'Plume': {
                'rang': 1,
                'description': 'Plume'
            },
            'Pki': {
                'rang': 1,
                'description': 'Pki'
            },
            'Parametres': {
                'rang': 1,
                'description': 'Parametres'
            },
            'Annuaire': {
                'rang': 1,
                'description': 'Annuaire'
            },
            'Backup': {
                'rang': 1,
                'description': 'Backup'
            },
            'Hebergement': {
                'rang': 1,
                'description': 'Hebergement'
            }
        },
        "menu": [
            'Principale',
            'Annuaire',
            'GrosFichiers',
            'Plume',
            'SenseursPassifs',
            'Pki',
            'Parametres',
            'Backup',
            'Hebergement',
        ]
    }

    # Document par defaut pour la configuration de l'interface principale
    DOCUMENT_DEFAUT = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
        TRANSACTION_MESSAGE_LIBELLE_VERSION: 7,
    }

    DOCUMENT_PROFIL_USAGER = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_PROFIL_USAGER,
        LIBELLE_COURRIEL: None,
        LIBELLE_PRENOM: None,
        LIBELLE_NOM: None,
        LIBELLE_TWITTER: None,
        LIBELLE_FACEBOOK: None,
    }

    DOCUMENT_PROFIL_MILLEGRILLE = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_PROFIL_MILLEGRILLE,
        LIBELLE_NOM_MILLEGRILLE: 'Sans nom',
        LIBELLE_LANGUE_PRINCIPALE: None,
        LIBELLE_LANGUES_ADDITIONNELLES: list(),
    }


class ConstantesSecurityPki:

    DELIM_DEBUT_CERTIFICATS = '-----BEGIN CERTIFICATE-----'
    COLLECTION_NOM = 'Pki/documents'

    LIBELLE_CERTIFICAT_PEM = 'certificat_pem'
    LIBELLE_FINGERPRINT = 'fingerprint'
    LIBELLE_CHAINE_PEM = 'chaine_pem'
    LIBELLE_CHAINE = 'chaine'
    LIBELLE_CERTIFICATS_PEM = 'certificats_pem'
    LIBELLE_CA_APPROUVE = 'ca_approuve'
    LIBELLE_IDMG = 'idmg'
    LIBELLE_CORRELATION_CSR = 'csr_correlation'

    EVENEMENT_CERTIFICAT = 'pki.certificat'  # Indique que c'est un evenement avec un certificat (reference)
    EVENEMENT_REQUETE = 'requete.certificat'  # Indique que c'est une requete pour trouver un certificat par fingerprint
    EVENEMENT_EMISSION_CERT = 'evenement.Pki'

    LIBVAL_CERTIFICAT_RACINE = 'certificat.root'
    LIBVAL_CERTIFICAT_MILLEGRILLE = 'certificat.millegrille'
    LIBVAL_CERTIFICAT_NOEUD = 'certificat.noeud'

    REQUETE_CORRELATION_CSR = 'pki.correlation_csr'

    REGLE_LIMITE_CHAINE = 4  # Longeur maximale de la chaine de certificats

    SYMETRIC_PADDING = 128

    ROLE_CONNECTEUR = 'connecteur'
    ROLE_MAITREDESCLES = 'maitrecles'

    # Document utilise pour publier un certificat
    DOCUMENT_EVENEMENT_CERTIFICAT = {
        EVENEMENT_MESSAGE_EVENEMENT: EVENEMENT_CERTIFICAT,
        LIBELLE_FINGERPRINT: None,
        LIBELLE_CERTIFICAT_PEM: None
    }


class ConstantesPki:
    DOMAINE_NOM = 'Pki'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_NOM_CERTIFICATS = '%s.certificats' % QUEUE_NOM

    TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT = '%s.nouveauCertificat' % DOMAINE_NOM
    TRANSACTION_WEB_NOUVEAU_CERTIFICAT = '%s.nouveauCertificat.web' % DOMAINE_NOM
    TRANSACTION_CLES_RECUES = '%s.clesRecues' % DOMAINE_NOM
    TRANSACTION_RENOUVELLER_CERT_DOCKER = '%s.renouvellerCertDocker' % DOMAINE_NOM

    LIBELLE_CERTIFICAT_PEM = ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM
    LIBELLE_FINGERPRINT = ConstantesSecurityPki.LIBELLE_FINGERPRINT
    LIBELLE_IDMG = 'idmg'
    LIBELLE_FINGERPRINT_ISSUER = 'fingerprint_issuer'
    LIBELLE_DOCID_ISSUER = '_id_issuer'
    LIBELLE_CHAINE_COMPLETE = 'chaine_complete'
    LIBELLE_SUBJECT = 'sujet'
    LIBELLE_ISSUER = 'issuer'
    LIBELLE_NOT_VALID_BEFORE = 'not_valid_before'
    LIBELLE_NOT_VALID_AFTER = 'not_valid_after'
    LIBELLE_SUBJECT_KEY = 'subject_key'
    LIBELLE_AUTHORITY_KEY = 'authority_key'
    LIBELLE_TRANSACTION_FAITE = 'transaction_faite'
    LIBELLE_CHAINES = 'chaines'
    LIBELLE_MGLIBELLE = 'mg-libelle'
    LIBELLE_CLE_CRYPTEE = 'cle_cryptee'
    LIBELLE_ROLES = 'roles'
    LIBELLE_EXCHANGES = 'exchanges'
    LIBELLE_DOMAINES = 'domaines'
    LIBELLE_CLE = 'cle'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_CERTIFICAT_ROOT = 'certificat.root'
    LIBVAL_CERTIFICAT_INTERMEDIAIRE = 'certificat.intermediaire'
    LIBVAL_CERTIFICAT_MILLEGRILLE = 'certificat.millegrille'
    LIBVAL_CERTIFICAT_NOEUD = 'certificat.noeud'
    LIBVAL_CERTIFICAT_BACKUP = 'certificat.backup'
    LIBVAL_LISTE_CERTIFICATS_BACKUP = 'liste.certificats.backup'
    LIBVAL_PKI_WEB = 'pki.web'
    LIBVAL_CONFIG_CERTDOCKER = 'configuration.certdocker'

    CHAMP_ALT_DOMAINS = 'altdomains'
    CHAMP_ROLES = 'roles'

    REQUETE_CONFIRMER_CERTIFICAT = 'confirmerCertificat'
    # REQUETE_CERTIFICAT_EMIS = 'evenement.Pki.infoCertificat'
    EVENEMENT_CERTIFICAT_EMIS = 'evenement.certificat.infoCertificat'
    REQUETE_CERTIFICAT_DEMANDE = 'requete.certificat'  # requete.certificat.__fingerprint__
    REQUETE_CERTIFICAT_BACKUP = 'certificatBackup'
    REQUETE_CERTIFICAT = 'requeteCertificat'
    REQUETE_LISTE_CA = 'requete.Pki.ca'
    REQUETE_LISTE_CERTS_CA = 'certificatsCA'
    TRANSACTION_EVENEMENT_CERTIFICAT = 'certificat'  # Indique que c'est une transaction avec un certificat a ajouter

    COMMANDE_SAUVEGADER_CERTIFICAT = 'certificat'  # Commande pour s'assurer d'avoir un certificat

    # Indique que c'est un evenement avec un certificat (reference)
    EVENEMENT_CERTIFICAT = ConstantesSecurityPki.EVENEMENT_CERTIFICAT
    # Indique que c'est une requete pour trouver un certificat par fingerprint
    EVENEMENT_REQUETE = ConstantesSecurityPki.EVENEMENT_REQUETE

    # Document par defaut pour la configuration de l'interface principale
    DOCUMENT_DEFAUT = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
        LIBELLE_FINGERPRINT: LIBVAL_CONFIGURATION,
    }

    DOCUMENT_CERTIFICAT_NOEUD = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CERTIFICAT_NOEUD,
        LIBELLE_CERTIFICAT_PEM: '',
        LIBELLE_FINGERPRINT: '',
        LIBELLE_CHAINE_COMPLETE: False
    }

    DOCUMENT_CONFIG_CERTDOCKER = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIG_CERTDOCKER,
        LIBELLE_FINGERPRINT: LIBVAL_CONFIG_CERTDOCKER,
        CHAMP_ALT_DOMAINS: dict(),
    }


class ConstantesParametres:

    DOMAINE_NOM = 'Parametres'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    COLLECTION_ERREURS = '%s/erreurs' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_ROUTING_CHANGEMENTS = 'noeuds.source.millegrilles_domaines_Parametres.documents'

    TRANSACTION_MODIFIER_EMAIL_SMTP = '%s.modifierEmailSmtp' % DOMAINE_NOM
    TRANSACTION_CLES_RECUES = '%s.clesRecues' % DOMAINE_NOM
    TRANSACTION_ETAT_ROUTEUR = '%s.public.routeur.etatRouteur' % DOMAINE_NOM
    TRANSACTION_EXPOSER_PORTS_ROUTEUR = '%s.public.routeur.exposerPorts' % DOMAINE_NOM
    TRANSACTION_RETIRER_PORTS_ROUTEUR = '%s.public.routeur.retirerPorts' % DOMAINE_NOM
    TRANSACTION_CONFIRMATION_ROUTEUR = '%s.public.routeur.confirmerAction' % DOMAINE_NOM
    TRANSACTION_SAUVER_CONFIG_PUBLIC = '%s.public.sauvegarder' % DOMAINE_NOM
    TRANSACTION_DEPLOYER_ACCES_PUBLIC = '%s.public.deployer' % DOMAINE_NOM
    TRANSACTION_RETIRER_ACCES_PUBLIC = '%s.public.retirer' % DOMAINE_NOM
    TRANSACTION_RENOUVELLER_CERTIFICAT_PUBLIC = '%s.public.renouvellerCertificat' % DOMAINE_NOM
    TRANSACTION_MAJ_CERTIFICAT_PUBLIC = '%s.public.majCertificat' % DOMAINE_NOM
    TRANSACTION_PRIVATISER_NOEUD = '%s.public.privatiser' % DOMAINE_NOM
    TRANSACTION_FERMER_MILLEGRILLE = '%s.fermerMilleGrilles' % DOMAINE_NOM
    TRANSACTION_MAJ_NOEUD_PUBLIC = '%s.majNoeudPublic' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_NOEUD_PUBLIC = '%s.supprimerNoeudPublic' % DOMAINE_NOM
    TRANSACTION_RECEPTION_CLES_MAJNOEUDPUBLIC = '%s.majNoeudPublic.clesRecues' % DOMAINE_NOM

    TRANSACTION_CHAMP_MGLIBELLE = 'mg-libelle'
    TRANSACTION_CHAMP_UUID = 'uuid'

    REQUETE_NOEUD_PUBLIC = 'noeudPublic'
    REQUETE_ERREURS = DOMAINE_NOM + '.erreurs'

    COMMANDE_SUPPRIMER_ERREUR = 'supprimerErreur'

    # Courriel
    DOCUMENT_CHAMP_COURRIEL_ORIGINE = 'origine'
    DOCUMENT_CHAMP_COURRIEL_DESTINATIONS = 'destinations'
    DOCUMENT_CHAMP_HOST = 'host'
    DOCUMENT_CHAMP_PORT = 'port'
    DOCUMENT_CHAMP_USER = 'user'
    DOCUMENT_CHAMP_PASSWORD = 'password'
    DOCUMENT_CHAMP_IDMG = 'idmg'
    DOCUMENT_CHAMP_URL_BASE = 'adresse_url_base'
    DOCUMENT_CHAMP_ACTIF = 'actif'

    DOCUMENT_CHAMP_MODE_DEPLOIEMENT = 'mode_deploiement'

    DOCUMENT_CHAMP_AWS_ACCESS_KEY = 'awsAccessKeyId'
    DOCUMENT_CHAMP_AWS_SECRET_KEY_CHIFFRE = 'awsSecretAccessKeyChiffre'
    DOCUMENT_CHAMP_AWS_CRED_REGION = 'awsCredentialRegion'
    DOCUMENT_CHAMP_AWS_BUCKET_NAME= 'awsBucketName'
    DOCUMENT_CHAMP_AWS_BUCKET_REGION = 'awsBucketRegion'
    DOCUMENT_CHAMP_AWS_BUCKET_URL = 'awsBucketUrl'
    DOCUMENT_CHAMP_AWS_BUCKET_DIR = 'awsBucketDir'

    TOKEN_ATTENTE_CLE = 'confirmer_reception_cle'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_EMAIL_SMTP = 'email.stmp'
    LIBVAL_VERSIONS_IMAGES_DOCKER = 'versions.images.docker'
    LIBVAL_CERTS_WEB = 'certs.web'
    LIBVAL_CERTS_SSL = 'certs.ssl'
    LIBVAL_ID_MILLEGRILLE = 'millegrille.id'
    LIBVAL_CONFIGURATION_NOEUDPUBLIC = 'configuration.noeudPublic'

    # Configuration Publique
    LIBVAL_CONFIGURATION_PUBLIQUE = 'publique.configuration'
    DOCUMENT_PUBLIQUE_ACTIF = 'actif'
    DOCUMENT_PUBLIQUE_UPNP_SUPPORTE = 'upnp_supporte'
    DOCUMENT_PUBLIQUE_NOEUD_DOCKER = 'noeud_docker_hostname'
    DOCUMENT_PUBLIQUE_NOEUD_DOCKER_ID = 'noeud_docker_id'
    DOCUMENT_PUBLIQUE_URL_WEB = 'url_web'
    DOCUMENT_PUBLIQUE_URL_COUPDOEIL = 'url_coupdoeil'
    DOCUMENT_PUBLIQUE_URL_MQ = 'url_mq'
    DOCUMENT_PUBLIQUE_PORT_HTTP = 'port_http'
    DOCUMENT_PUBLIQUE_PORT_HTTPS = 'port_https'
    DOCUMENT_PUBLIQUE_PORT_MQ = 'port_mq'
    DOCUMENT_PUBLIQUE_PORT_EXTERIEUR = 'port_ext'
    DOCUMENT_PUBLIQUE_PORT_INTERNE = 'port_int'
    DOCUMENT_PUBLIQUE_IPV4_EXTERNE = 'ipv4_externe'
    DOCUMENT_PUBLIQUE_IPV4_INTERNE = 'ipv4_interne'
    DOCUMENT_PUBLIQUE_PROTOCOL = 'protocol'
    DOCUMENT_PUBLIQUE_PORT_MAPPING_NOM = 'port_mapping_nom'
    DOCUMENT_PUBLIQUE_MAPPINGS_IPV4 = 'mappings_ipv4'
    DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES = 'mappings_ipv4_demandes'
    DOCUMENT_PUBLIQUE_ROUTEUR_STATUS = 'status_info'
    DOCUMENT_PUBLIQUE_ACTIVITE = 'activite'

    DOCUMENT_PUBLIQUE_ACTIVITE_DATE = 'date'
    DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION = 'description'

    DOCUMENT_PUBLIQUE_ACTIVITE_TAILLEMAX = 50

    DOCUMENT_PUBLIQUE_MENU = 'menu'

    DOCUMENT_DEFAUT = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    DOCUMENT_ID_MILLEGRILLE = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_ID_MILLEGRILLE,
        DOCUMENT_CHAMP_IDMG: 'Sansnom',
        DOCUMENT_CHAMP_URL_BASE: 'sansnom.millegrilles.com',
    }

    DOCUMENT_EMAIL_SMTP = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_EMAIL_SMTP,
        DOCUMENT_CHAMP_ACTIF: False,
        DOCUMENT_CHAMP_COURRIEL_ORIGINE: None,
        DOCUMENT_CHAMP_COURRIEL_DESTINATIONS: None,
        DOCUMENT_CHAMP_HOST: None,
        DOCUMENT_CHAMP_PORT: None,
        DOCUMENT_CHAMP_USER: None,
        DOCUMENT_SECTION_CRYPTE: None,  # DOCUMENT_CHAMP_PASSWORD
    }

    DOCUMENT_CONFIGURATION_PUBLIQUE = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION_PUBLIQUE,
        DOCUMENT_PUBLIQUE_ACTIF: False,
        DOCUMENT_PUBLIQUE_NOEUD_DOCKER: None,
        DOCUMENT_PUBLIQUE_UPNP_SUPPORTE: False,
        DOCUMENT_PUBLIQUE_URL_WEB: None,
        DOCUMENT_PUBLIQUE_URL_MQ: None,
        DOCUMENT_PUBLIQUE_IPV4_EXTERNE: None,
        DOCUMENT_PUBLIQUE_ROUTEUR_STATUS: None,
        DOCUMENT_PUBLIQUE_PORT_HTTP: 80,
        DOCUMENT_PUBLIQUE_PORT_HTTPS: 443,
        DOCUMENT_PUBLIQUE_PORT_MQ: 5673,

        # Cle: port exterieur, Valeur: DOCUMENT_CONFIGURATION_PUBLIQUE_MAPPINGS
        DOCUMENT_PUBLIQUE_MAPPINGS_IPV4: dict(),
        DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES: dict(),
        DOCUMENT_PUBLIQUE_ACTIVITE: list(),
    }

    DOCUMENT_CONFIGURATION_PUBLIQUE_MAPPINGS = {
        DOCUMENT_PUBLIQUE_PORT_EXTERIEUR: None,
        DOCUMENT_PUBLIQUE_IPV4_INTERNE: None,
        DOCUMENT_PUBLIQUE_PORT_INTERNE: None,
        DOCUMENT_PUBLIQUE_PORT_MAPPING_NOM: None,
    }

    DOCUMENT_CONFIGURATION_PUBLIQUE_ACTIVITE = {
        DOCUMENT_PUBLIQUE_ACTIVITE_DATE: datetime.datetime.utcnow(),
        DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION: '',
    }


class ConstantesMaitreDesCles:

    DOMAINE_NOM = 'MaitreDesCles'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_CLES_NOM = '%s/cles' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM

    LIBVAL_CONFIGURATION = 'configuration'

    # TRANSACTION_NOUVELLE_CLE = 'nouvelleCle'
    TRANSACTION_CLE = 'cle'

    # TRANSACTION_NOUVELLE_CLE_GROSFICHIER = '%s.cleGrosFichier' % DOMAINE_NOM
    # TRANSACTION_NOUVELLE_CLE_GROSFICHIER_BACKUP = 'cleGrosFichierBackup'
    # TRANSACTION_NOUVELLE_CLE_BACKUPTRANSACTIONS = '%s.cleBackupTransactions' % DOMAINE_NOM
    # TRANSACTION_NOUVELLE_CLE_BACKUPTRANSACTIONS_BACKUP = 'cleBackupTransactionsBackup'
    # TRANSACTION_NOUVELLE_CLE_BACKUPAPPLICATION = 'cleBackupApplication'
    # TRANSACTION_NOUVELLE_CLE_BACKUPAPPLICATION_BACKUP = 'cleBackupApplicationBackup'
    # TRANSACTION_NOUVELLE_CLE_DOCUMENT = '%s.cleDocument' % DOMAINE_NOM
    # TRANSACTION_NOUVELLE_CLE_DOCUMENT_BACKUP = 'cleDocumentBackup'
    # TRANSACTION_MAJ_DOCUMENT_CLES = '%s.majcles' % DOMAINE_NOM
    # TRANSACTION_MAJ_MOTDEPASSE = '%s.maj_motdepasse' % DOMAINE_NOM

    # TRANSACTION_DOMAINES_DOCUMENT_CLESRECUES = 'clesRecues'
    # TRANSACTION_RENOUVELLEMENT_CERTIFICAT = '%s.renouvellementCertificat' % DOMAINE_NOM
    # TRANSACTION_SIGNER_CERTIFICAT_NOEUD = '%s.signerCertificatNoeud' % DOMAINE_NOM
    # TRANSACTION_GENERER_CERTIFICAT_NAVIGATEUR = '%s.genererCertificatNavigateur' % DOMAINE_NOM
    # TRANSACTION_DECLASSER_CLE_GROSFICHIER = '%s.declasserCleGrosFichier' % DOMAINE_NOM
    # TRANSACTION_GENERER_DEMANDE_INSCRIPTION = '%s.genererDemandeInscription' % DOMAINE_NOM
    # TRANSACTION_GENERER_CERTIFICAT_POUR_TIERS = '%s.genererCertificatPourTiers' % DOMAINE_NOM

    # TRANSACTION_HEBERGEMENT_NOUVEAU_TROUSSEAU = '%s.nouveauTrousseauHebergement' % DOMAINE_NOM
    # TRANSACTION_HEBERGEMENT_MAJ_TROUSSEAU = '%s.majTrousseauHebergement' % DOMAINE_NOM
    # TRANSACTION_HEBERGEMENT_MOTDEPASSE_CLE = '%s.nouveauMotDePasseCleHebergement' % DOMAINE_NOM
    # TRANSACTION_HEBERGEMENT_SUPPRIMER = '%s.supprimerHebergement' % DOMAINE_NOM

    # REQUETE_CLE_RACINE = 'requeteCleRacine'
    REQUETE_CERT_MAITREDESCLES = 'certMaitreDesCles'

    REQUETE_DECHIFFRAGE = 'dechiffrage'

    # REQUETE_DECRYPTAGE_DOCUMENT = 'decryptageDocument'
    # REQUETE_DECRYPTAGE_GROSFICHIER = 'decryptageGrosFichier'
    # REQUETE_TROUSSEAU_HEBERGEMENT = 'trousseauHebergement'
    REQUETE_CLES_NON_DECHIFFRABLES = 'clesNonDechiffrables'
    REQUETE_COMPTER_CLES_NON_DECHIFFRABLES = 'compterClesNonDechiffrables'
    # REQUETE_DECHIFFRAGE_BACKUP = 'dechiffrageBackup'
    REQUETE_COLLECTIONS_PUBLIQUES = 'collectionsPubliques'

    # COMMANDE_SIGNER_CLE_BACKUP = 'signerCleBackup'
    COMMANDE_RESTAURER_BACKUP_CLES = 'restaurerBackupCles'
    # COMMANDE_CREER_CLES_MILLEGRILLE_HEBERGEE = 'creerClesMilleGrilleHebergee'
    # COMMANDE_SIGNER_CSR = 'signerCsr'
    # COMMANDE_SIGNER_NAVIGATEUR_CSR = 'signerNavigateurCsr'
    # COMMANDE_SIGNER_CSR_CA_DEPENDANT = 'signerCSRCADependant'
    COMMANDE_SAUVEGARDER_CLE = 'sauvegarderCle'

    CORRELATION_CERTIFICATS_BACKUP = 'certificatsBackup'

    TRANSACTION_CHAMP_CLESECRETE = 'cle'
    TRANSACTION_CHAMP_CLE_INDIVIDUELLE = 'cle'
    TRANSACTION_CHAMP_CLES = 'cles'
    TRANSACTION_CHAMP_IV = 'iv'
    TRANSACTION_CHAMP_TAG = 'tag'
    TRANSACTION_CHAMP_FORMAT = 'format'
    TRANSACTION_CHAMP_FINGERPRINT = 'fingerprint'
    TRANSACTION_CHAMP_SUJET_CLE = 'sujet'
    TRANSACTION_CHAMP_DOMAINE = 'domaine'
    TRANSACTION_CHAMP_DOMAINES = 'domaines'
    TRANSACTION_CHAMP_IDDOC = 'id-doc'
    TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS = 'identificateurs_document'
    TRANSACTION_CHAMP_MGLIBELLE = 'mg-libelle'
    TRANSACTION_CHAMP_ROLE_CERTIFICAT = 'role'
    TRANSACTION_CHAMP_CSR = 'csr'
    TRANSACTION_CHAMP_CSR_CORRELATION = 'csr_correlation'
    TRANSACTION_CHAMP_TYPEDEMANDE = 'type_demande'
    TRANSACTION_CHAMP_FULLCHAIN = 'certificat_fullchain_signataire'
    TRANSACTION_CHAMP_MOTDEPASSE = 'motdepasse'
    TRANSACTION_CHAMP_SYNCHRONISER = 'synchroniser'
    TRANSACTION_CHAMP_MILLEGRILLE = 'millegrille'
    TRANSACTION_CHAMP_INTERMEDIAIRE = 'intermediaire'
    TRANSACTION_CHAMP_HEBERGEMENT = 'hebergement'
    TRANSACTION_CHAMP_HOTE = 'hote'
    TRANSACTION_CHAMP_HOTE_PEM = 'hote_pem'
    TRANSACTION_CHAMP_ROLES_PERMIS = 'roles_permis'
    TRANSACTION_CHAMP_CERTIFICAT_TIERS = '_certificat_tiers'
    TRANSACTION_CHAMP_DUREE_PERMISSION = 'duree'
    TRANSACTION_CHAMP_UUID_ORIGINAL = 'uuid_original'
    TRANSACTION_CHAMP_HACHAGE_BYTES = 'hachage_bytes'
    TRANSACTION_CHAMP_NON_DECHIFFRABLE = 'non_dechiffrable'
    TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES = 'liste_hachage_bytes'

    TYPE_DEMANDE_INSCRIPTION = 'inscription'

    TRANSACTION_VERSION_COURANTE = 5

    TOKEN_SYNCHRONISER = 'synchroniser'

    DOCUMENT_LIBVAL_CLE = 'cle'
    # DOCUMENT_LIBVAL_CLES_GROSFICHIERS = 'cles.grosFichiers'
    # DOCUMENT_LIBVAL_CLES_BACKUPTRANSACTIONS = 'cles.backupTransactions'
    # DOCUMENT_LIBVAL_CLES_DOCUMENT = 'cles.document'
    # DOCUMENT_LIBVAL_CLES_BACKUPAPPLICATION = 'cles.backupApplication'
    # DOCUMENT_LIBVAL_MOTDEPASSE = 'motdepasse.document'
    # DOCUMENT_LIBVAL_HEBERGEMENT_TROUSSEAU = 'hebergement.trousseau'

    DOCUMENT_SECURITE = 'securite'

    DOCUMENT_DEFAUT = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
        TRANSACTION_MESSAGE_LIBELLE_VERSION: TRANSACTION_VERSION_COURANTE
    }

    # Document utilise pour conserver un ensemble de cles lie a un document
    # DOCUMENT_CLES_GROSFICHIERS = {
    #     DOCUMENT_INFODOC_LIBELLE: DOCUMENT_LIBVAL_CLES_GROSFICHIERS,
    #
    #     # Template a remplir
    #     'fuuid': None,    # Identificateur unique de version de fichier
    #     'cles': dict(),   # Dictionnaire indexe par fingerprint de certificat signataire. Valeur: cle secrete cryptee
    # }

    # DOCUMENT_TRANSACTION_CONSERVER_CLES = {
    #     TRANSACTION_CHAMP_SUJET_CLE: DOCUMENT_LIBVAL_CLES_GROSFICHIERS,  # Mettre le sujet approprie
    #     'cles': dict(),  # Dictionnaire indexe par fingerprint de certificat signataire. Valeur: cle secrete cryptee
    # }

    DOCUMENT_TRANSACTION_GROSFICHIERRESUME = {
        'fuuid': None,  # Identificateur unique de version de fichier
    }


class ConstantesPlume:

    DOMAINE_NOM = 'Posteur'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_ROUTING_CHANGEMENTS = 'evenement.%s.document' % DOMAINE_NOM

    TRANSACTION_NOUVEAU_DOCUMENT = '%s.nouveauDocument' % DOMAINE_NOM
    TRANSACTION_MODIFIER_DOCUMENT = '%s.modifierDocument' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_DOCUMENT = '%s.supprimerDocument' % DOMAINE_NOM
    TRANSACTION_PUBLIER_DOCUMENT = '%s.publierDocument' % DOMAINE_NOM
    TRANSACTION_DEPUBLIER_DOCUMENT = '%s.depublierDocument' % DOMAINE_NOM
    TRANSACTION_CREER_ANNONCE = '%s.creerAnnonce' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_ANNONCE = '%s.supprimerAnnonce' % DOMAINE_NOM
    TRANSACTION_MAJ_ACCUEIL_VITRINE = '%s.majAccueilVitrine' % DOMAINE_NOM
    TRANSACTION_MAJ_BLOGPOST = '%s.majBlogpostVitrine' % DOMAINE_NOM
    TRANSACTION_PUBLIER_BLOGPOST = '%s.publierBlogpostVitrine' % DOMAINE_NOM
    TRANSACTION_RETIRER_BLOGPOST = '%s.retirerBlogpostVitrine' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_BLOGPOST = '%s.supprimerBlogpostVitrine' % DOMAINE_NOM

    REQUETE_CHARGER_ANNONCES_RECENTES = 'chargerAnnoncesRecentes'
    REQUETE_CHARGER_ANNONCES = 'chargerAnnonces'
    REQUETE_CHARGER_ACCUEIL = 'chargerAccueil'
    REQUETE_CHARGER_BLOGPOSTS_RECENTS = DOMAINE_NOM + '.chargerBlogpostsRecents'
    REQUETE_CHARGER_BLOGPOSTS = 'chargerBlogposts'
    REQUETE_CHARGER_BLOGPOST = DOMAINE_NOM + '.chargerBlogpost'

    LIBELLE_DOC_PLUME_UUID = 'uuid'
    LIBELLE_DOC_SECURITE = 'securite'
    LIBELLE_DOC_TITRE = 'titre'
    LIBELLE_DOC_CATEGORIES = 'categories'
    LIBELLE_DOC_TEXTE = 'texte'
    LIBELLE_DOC_SUJET = 'sujet'
    LIBELLE_DOC_QUILL_DELTA = 'quilldelta'
    LIBELLE_DOC_LISTE = 'documents'
    LIBELLE_DOC_DATE_PUBLICATION = 'datePublication'
    LIBELLE_DOC_REMPLACE = 'remplace'
    LIBELLE_DOC_DATE_ATTENTE_PUBLICATION = 'dateAttentePublication'
    LIBELLE_DOC_ANNONCES = 'annonces'
    LIBELLE_DOC_IMAGE = 'image'
    LIBELLE_DOC_BLOGPOSTS = 'blogposts'

    LIBELLE_DOC_VITRINE_BIENVENUE = 'messageBienvenue'
    LIBELLE_DOC_VITRINE_TITRE_COLONNES = 'titreCol'
    LIBELLE_DOC_VITRINE_TEXTE_COLONNES = 'texteCol'

    DEFAUT_ATTENTE_PUBLICATION_SECS = 120   # Delai de publication par defaut
    DEFAUT_NOMBRE_ANNONCES_RECENTES = 200   # Nombre max d'annonces dans annonces.recentes

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_PLUME = 'plume'
    LIBVAL_ANNONCE = 'annonce'
    LIBVAL_ANNONCES_RECENTES = 'annonces.recentes'
    LIBVAL_CATALOGUE = 'catalogue'
    LIBVAL_CATEGORIE = 'categorie'
    LIBVAL_VITRINE_ACCUEIL = 'vitrine.accueil'
    LIBVAL_BLOGPOST = 'blogpost'
    LIBVAL_BLOGPOSTS_RECENTS = 'blogposts.recents'

    DOCUMENT_DEFAUT = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    DOCUMENT_PLUME = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_PLUME,
        LIBELLE_DOC_PLUME_UUID: None,  # Identificateur unique du document plume
        LIBELLE_DOC_SECURITE: SECURITE_PRIVE,  # Niveau de securite
        LIBELLE_DOC_TITRE: None,               # Titre
        LIBELLE_DOC_CATEGORIES: None,          # Categorie du fichier
        LIBELLE_DOC_QUILL_DELTA: None,         # Contenu, delta Quill
        LIBELLE_DOC_TEXTE: None,               # Texte sans formattage
    }

    DOCUMENT_CATALOGUE = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CATALOGUE,
        LIBELLE_DOC_SECURITE: SECURITE_PUBLIC,     # Niveau de securite du catalogue
        LIBELLE_DOC_CATEGORIES: {},                # Dict des categories de Plume. Valeur est 'True' (bidon)
        LIBELLE_DOC_LISTE: {},                     # Dict des documents du catalogue. Cle est uuid,
                                                # valeur est: {titre, uuid, _mg-derniere-modification, categories).
    }

    DOCUMENT_ANNONCE = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_ANNONCE,
        LIBELLE_DOC_SUJET: None,                        # Sujet du message (opt)
        LIBELLE_DOC_TEXTE: None,                        # Texte sans formattage
        LIBELLE_DOC_REMPLACE: None,                     # uuid de l'annonce remplacee (opt)
        LIBELLE_DOC_DATE_ATTENTE_PUBLICATION: None,     # Date de prise d'effet de l'annonce
    }

    DOCUMENT_ANNONCES_RECENTES = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_ANNONCES_RECENTES,
        LIBELLE_DOC_ANNONCES: list(),   # Liste triee par date, plus recente annonce en premier
    }

    DOCUMENT_VITRINE_ACCUEIL = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_VITRINE_ACCUEIL,
    }

    DOCUMENT_BLOGPOSTS_RECENTS = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_BLOGPOSTS_RECENTS,
        LIBELLE_DOC_BLOGPOSTS: dict(),
    }

    FILTRE_DOC_ANNONCES_RECENTES = [
        DOCUMENT_INFODOC_DATE_CREATION,
        DOCUMENT_INFODOC_DERNIERE_MODIFICATION,
        LIBELLE_DOC_PLUME_UUID,
        LIBELLE_DOC_DATE_ATTENTE_PUBLICATION,
        LIBELLE_DOC_TEXTE,
        LIBELLE_DOC_SUJET
    ]


class ConstantesGrosFichiers:
    """ Constantes pour le domaine de GrosFichiers """

    DOMAINE_NOM = 'GrosFichiers'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_ROUTING_CHANGEMENTS = 'noeuds.source.millegrilles_domaines_GrosFichiers'

    TRANSACTION_TYPE_METADATA = 'millegrilles.domaines.GrosFichiers.nouvelleVersion.metadata'
    TRANSACTION_TYPE_TRANSFERTCOMPLETE = 'millegrilles.domaines.GrosFichiers.nouvelleVersion.transfertComplete'

    TRANSACTION_CHAMP_ETIQUETTE = 'etiquette'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_FICHIER = 'fichier'
    LIBVAL_COLLECTION = 'collection'
    LIBVAL_COLLECTION_FIGEE = 'collection.figee'
    LIBVAL_RAPPORT = 'rapport'
    LIBVAL_RAPPORT_ACTIVITE = 'rapport.activite'
    LIBVAL_CONVERSION_MEDIA = 'conversionMedia'
    LIBVAL_PUBLICATION_FICHIERS = 'publicationFichiers'
    LIBVAL_UPLOAD_AWSS3 = 'uploadAwss3'

    LIBVAL_VITRINE_FICHIERS = 'vitrine.fichiers'
    LIBVAL_VITRINE_ALBUMS = 'vitrine.albums'

    LIBELLE_PUBLICATION_CACHERFICHIERS = 'cacherfichiers'
    LIBELLE_PUBLICATION_TOP = 'top'
    LIBELLE_PUBLICATION_CAROUSEL = 'carousel'

    DOCUMENT_SECURITE = 'securite'
    DOCUMENT_COMMENTAIRES = 'commentaires'

    DOCUMENT_REPERTOIRE_FICHIERS = 'fichiers'

    DOCUMENT_FICHIER_NOMFICHIER = 'nom_fichier'
    DOCUMENT_FICHIER_COMMENTAIRES = 'commentaires'
    DOCUMENT_FICHIER_EXTENSION_ORIGINAL = 'extension'
    DOCUMENT_FICHIER_UUID_DOC = 'uuid'                    # UUID du document de fichier (metadata)
    DOCUMENT_UUID_GENERIQUE = 'document_uuid'            # Represente un UUID de n'import quel type de document
    DOCUMENT_FICHIER_FUUID = 'fuuid'                    # UUID (v1) du fichier
    DOCUMENT_FICHIER_DATEVCOURANTE = 'date_v_courante'  # Date de la version courante
    DOCUMENT_FICHIER_UUIDVCOURANTE = 'fuuid_v_courante'  # FUUID de la version courante
    DOCUMENT_FICHIER_VERSIONS = 'versions'
    DOCUMENT_FICHIER_MIMETYPE = 'mimetype'
    DOCUMENT_FICHIER_TAILLE = 'taille'
    DOCUMENT_FICHIER_HACHAGE = 'hachage'
    DOCUMENT_FICHIER_SUPPRIME = 'supprime'
    DOCUMENT_FICHIER_ETIQUETTES = 'etiquettes'
    DOCUMENT_FICHIER_THUMBNAIL = 'thumbnail'
    DOCUMENT_FICHIER_DATA_VIDEO = 'data_video'
    DOCUMENT_FICHIER_FUUID_PREVIEW = 'fuuid_preview'
    DOCUMENT_FICHIER_METADATA = "metadata"
    DOCUMENT_FICHIER_METADATA_VIDEO = "data_video"
    DOCUMENT_FICHIER_MIMETYPE_PREVIEW = 'mimetype_preview'
    DOCUMENT_FICHIER_EXTENSION_PREVIEW = 'extension_preview'
    DOCUMENT_FICHIER_HACHAGE_PREVIEW = 'hachage_preview'
    DOCUMENT_FICHIER_FUUID_480P = "fuuidVideo480p"
    DOCUMENT_FICHIER_MIMETYPE_480P = "mimetypeVideo480p"
    DOCUMENT_FICHIER_TAILLE_480P = "tailleVideo480p"
    DOCUMENT_FICHIER_HACHAGE_VIDEO = "hachageVideo"
    DOCUMENT_FICHIER_COMMANDE_PERMISSION = 'permission'
    DOCUMENT_FICHIER_FLAG_PREVIEW = 'preview_traite'
    DOCUMENT_FICHIER_FUUID_ASSOCIES = 'fuuid_associes'

    DOCUMENT_FICHIER_FUUID_DECRYPTE = 'fuuid_decrypte'
    DOCUMENT_LISTE_UUIDS = 'uuids_documents'

    DOCUMENT_COLLECTION_NOMCOLLECTION = 'nom_collection'
    DOCUMENT_COLLECTION_FICHIERS = 'fichiers'
    DOCUMENT_COLLECTION_LISTEDOCS = 'documents'
    DOCUMENT_COLLECTION_DOCS_UUIDS = 'documents_uuids'
    DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE = 'uuid_source_figee'
    DOCUMENT_COLLECTIONS_FIGEES = 'figees'
    DOCUMENT_COLLECTION_UUID = 'uuid-collection'
    DOCUMENT_TORRENT_COLLECTION_UUID = 'uuid_collection_torrent'
    DOCUMENT_COLLECTION_FIGEE_DATE = 'date'
    DOCUMENT_COLLECTIONS = 'collections'
    DOCUMENT_FAVORIS = 'favoris'
    DOCUMENT_UUID_PARENT = 'uuid_parent'
    DOCUMENT_PREVIEWS = 'previews'
    DOCUMENT_VIDEO = 'video'
    DOCUMENT_TRANSCODAGE = 'transcodage'
    DOCUMENT_NOEUD_IDS_PUBLIES = 'noeud_ids_publies'
    DOCUMENT_DERNIERE_ACTIVITE = 'derniere_activite'
    DOCUMENT_PROGRES = 'progres'
    DOCUMENT_UPLOAD_LIST = 'upload_list'

    DOCUMENT_FAVORIS_LISTE = 'favoris'

    DOCUMENT_VITRINE_TOP = 'top'
    DOCUMENT_VITRINE_COLLECTIONS = 'collections'

    DOCUMENT_VERSION_NOMFICHIER = 'nom'
    DOCUMENT_VERSION_DATE_FICHIER = 'date_fichier'
    DOCUMENT_VERSION_DATE_VERSION = 'date_version'
    DOCUMENT_VERSION_DATE_SUPPRESSION = 'date_suppression'

    DOCUMENT_DEFAULT_MIMETYPE = 'application/binary'

    DOCUMENT_TORRENT_HASHSTRING = 'torrent_hashstring'

    TRANSACTION_NOUVELLEVERSION_METADATA = '%s.nouvelleVersion' % DOMAINE_NOM
    TRANSACTION_DEMANDE_THUMBNAIL_PROTEGE = '%s.demandeThumbnailProtege' % DOMAINE_NOM
    TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE = '%s.nouvelleVersion.transfertComplete' % DOMAINE_NOM
    TRANSACTION_NOUVELLEVERSION_CLES_RECUES = '%s.nouvelleVersion.clesRecues' % DOMAINE_NOM
    TRANSACTION_COPIER_FICHIER = '%s.copierFichier' % DOMAINE_NOM
    TRANSACTION_RENOMMER_DOCUMENT = '%s.renommerDocument' % DOMAINE_NOM
    TRANSACTION_COMMENTER_FICHIER = '%s.commenterFichier' % DOMAINE_NOM
    TRANSACTION_CHANGER_ETIQUETTES_FICHIER = '%s.changerEtiquettesFichier' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_FICHIER = '%s.supprimerDocuments' % DOMAINE_NOM
    TRANSACTION_RECUPERER_FICHIER = '%s.recupererDocuments' % DOMAINE_NOM
    TRANSACTION_DECRYPTER_FICHIER = '%s.decrypterFichier' % DOMAINE_NOM
    TRANSACTION_CLESECRETE_FICHIER = '%s.cleSecreteFichier' % DOMAINE_NOM
    TRANSACTION_NOUVEAU_FICHIER_DECRYPTE = '%s.nouveauFichierDecrypte' % DOMAINE_NOM
    TRANSACTION_ASSOCIER_THUMBNAIL = '%s.associerThumbnail' % DOMAINE_NOM
    TRANSACTION_ASSOCIER_VIDEO_TRANSCODE = '%s.associerVideo' % DOMAINE_NOM
    TRANSACTION_ASSOCIER_PREVIEW = '%s.associerPreview' % DOMAINE_NOM
    TRANSACTION_DECRIRE_FICHIER = 'decrireFichier'
    TRANSACTION_DECRIRE_COLLECTION = 'decrireCollection'

    TRANSACTION_NOUVELLE_COLLECTION = '%s.nouvelleCollection' % DOMAINE_NOM
    TRANSACTION_RENOMMER_COLLECTION = '%s.renommerCollection' % DOMAINE_NOM
    TRANSACTION_COMMENTER_COLLECTION = '%s.commenterCollection' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_COLLECTION = '%s.supprimerCollection' % DOMAINE_NOM
    TRANSACTION_RECUPERER_COLLECTION = '%s.recupererCollection' % DOMAINE_NOM
    TRANSACTION_FIGER_COLLECTION = '%s.figerCollection' % DOMAINE_NOM
    TRANSACTION_CHANGER_ETIQUETTES_COLLECTION = '%s.changerEtiquettesCollection' % DOMAINE_NOM
    TRANSACTION_CREERTORRENT_COLLECTION = '%s.creerTorrentCollection' % DOMAINE_NOM
    TRANSACTION_AJOUTER_FICHIERS_COLLECTION = '%s.ajouterFichiersCollection' % DOMAINE_NOM
    TRANSACTION_RETIRER_FICHIERS_COLLECTION = '%s.retirerDocumentsCollection' % DOMAINE_NOM
    TRANSACTION_CHANGER_SECURITE_COLLECTION = '%s.changerSecuriteCollection' % DOMAINE_NOM

    TRANSACTION_CHANGER_FAVORIS = '%s.changerFavoris' % DOMAINE_NOM

    TRANSACTION_TORRENT_NOUVEAU = '%s.nouveauTorrent' % DOMAINE_NOM
    TRANSACTION_TORRENT_SEEDING = '%s.seedingTorrent' % DOMAINE_NOM

    TRANSACTION_PUBLIER_COLLECTION = '%s.publierCollection' % DOMAINE_NOM

    EVENEMENTS_CONFIRMATION_MAJ_COLLECTIONPUBLIQUE = 'confirmationMajCollectionPublique'

    REQUETE_VITRINE_FICHIERS = '%s.vitrineFichiers' % DOMAINE_NOM
    REQUETE_VITRINE_ALBUMS = '%s.vitrineAlbums' % DOMAINE_NOM
    REQUETE_COLLECTION_FIGEE = '%s.collectionFigee' % DOMAINE_NOM
    REQUETE_ACTIVITE_RECENTE = '%s.activiteRecente' % DOMAINE_NOM
    REQUETE_CORBEILLE = '%s.getCorbeille' % DOMAINE_NOM
    REQUETE_COLLECTIONS = '%s.collections' % DOMAINE_NOM
    REQUETE_FAVORIS = '%s.favoris' % DOMAINE_NOM
    REQUETE_CONTENU_COLLECTION = '%s.contenuCollection' % DOMAINE_NOM
    REQUETE_DOCUMENTS_PAR_UUID = '%s.documentsParUuid' % DOMAINE_NOM
    REQUETE_DOCUMENT_PAR_FUUID = 'documentsParFuuid'
    REQUETE_PERMISSION_DECHIFFRAGE_PUBLIC = 'demandePermissionDechiffragePublic'
    REQUETE_COLLECTIONS_PUBLIQUES = 'collectionsPubliques'
    REQUETE_DETAIL_COLLECTIONS_PUBLIQUES = 'detailCollectionsPubliques'
    REQUETE_TRANSFERTS_EN_COURS = 'transfertsEnCours'

    COMMANDE_GENERER_THUMBNAIL_PROTEGE = 'commande.grosfichiers.genererThumbnailProtege'
    COMMANDE_REGENERER_PREVIEWS = 'regenererPreviews'
    COMMANDE_TRANSCODER_VIDEO = 'transcoderVideo'
    COMMANDE_RESET_FICHIERS_PUBLIES = 'resetFichiersPublies'
    COMMANDE_CLEAR_FICHIER_PUBLIE = 'clearFichierPublie'
    COMMANDE_UPLOAD_COLLECTIONS_PUBLIQUES = 'uploadCollectionsPubliques'

    # Document par defaut pour la configuration de l'interface GrosFichiers
    DOCUMENT_DEFAUT = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
    }

    DOCUMENT_FICHIER = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_FICHIER,
        DOCUMENT_FICHIER_UUID_DOC: None,  # Identificateur unique du fichier (UUID trans initiale)
        # DOCUMENT_SECURITE: Constantes.SECURITE_SECURE,      # Niveau de securite
        DOCUMENT_COMMENTAIRES: None,                        # Commentaires
        DOCUMENT_FICHIER_NOMFICHIER: None,                  # Nom du fichier (libelle affiche a l'usager)
        DOCUMENT_FICHIER_ETIQUETTES: list(),                # Liste de libelles du fichier
        DOCUMENT_FICHIER_SUPPRIME: False,                   # True si le fichier est supprime
    }

    SOUSDOCUMENT_VERSION_FICHIER = {
        DOCUMENT_FICHIER_FUUID: None,
        DOCUMENT_FICHIER_NOMFICHIER: None,
        DOCUMENT_FICHIER_MIMETYPE: DOCUMENT_DEFAULT_MIMETYPE,
        DOCUMENT_VERSION_DATE_FICHIER: None,
        DOCUMENT_VERSION_DATE_VERSION: None,
        DOCUMENT_FICHIER_TAILLE: None,
        DOCUMENT_FICHIER_HACHAGE: None,
        DOCUMENT_COMMENTAIRES: None,
    }

    DOCUMENT_COLLECTION = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_COLLECTION,
        DOCUMENT_FICHIER_UUID_DOC: None,        # Identificateur unique du fichier (UUID trans initiale)
        DOCUMENT_FICHIER_ETIQUETTES: list(),    # Etiquettes de la collection
        DOCUMENT_FICHIER_SUPPRIME: False,       # True si la collection est supprimee
        DOCUMENT_COMMENTAIRES: None,
        DOCUMENT_SECURITE: SECURITE_PROTEGE,
    }

    DOCUMENT_COLLECTION_FICHIER = {
        DOCUMENT_FICHIER_UUID_DOC: None,    # uuid du fichier
        DOCUMENT_FICHIER_FUUID: None,       # fuuid de la version du fichier
        DOCUMENT_FICHIER_NOMFICHIER: None,  # Nom du fichier
        DOCUMENT_VERSION_DATE_FICHIER: None,
        DOCUMENT_FICHIER_TAILLE: None,
        DOCUMENT_COMMENTAIRES: None,
    }

    DOCUMENT_VITRINE_FICHIERS = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_VITRINE_FICHIERS,
        DOCUMENT_VITRINE_TOP: dict(),
        DOCUMENT_VITRINE_COLLECTIONS: dict(),
    }

    DOCUMENT_VITRINE_ALBUMS = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_VITRINE_ALBUMS,
        DOCUMENT_VITRINE_TOP: dict(),
        DOCUMENT_VITRINE_COLLECTIONS: dict(),
    }

    # Prototype de document liste de recherche
    # Represente une liste maintenue et triee par un champ particulier (date) de resultats
    # pour acces rapide.
    # Peut etre utilise pour garder une liste des N derniers fichiers changes, fichiers
    # avec libelles '2019 et 'photos', etc.
    DOCUMENT_RAPPORT_RECHERCHE = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_RAPPORT,
        'description': None,                    # Description (nom) de la liste de recherche
        DOCUMENT_SECURITE: None,                # Niveau de securite de cette liste
        'filtre_libelles': dict(),              # Libelles utilises pour filtrer la liste des changements
        DOCUMENT_COLLECTION_FICHIERS: list(),   # Dictionnaire de fichiers, valeur=DOCUMENT_COLLECTION_FICHIER
        'tri': [{DOCUMENT_VERSION_DATE_FICHIER: -1}],   # Tri de la liste, utilise pour tronquer
        'compte_max': 100,                      # Nombre maximal d'entree dans la liste
    }


# Constantes pour SenseursPassifs
class SenseursPassifsConstantes:

    DOMAINE_NOM = 'SenseursPassifs'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_STAGING_NOM = '%s/staging' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_NOEUDS_NOM = '%s.noeuds' % DOMAINE_NOM
    QUEUE_INTER_NOM = '%s.inter' % DOMAINE_NOM
    # QUEUE_ROUTING_CHANGEMENTS = 'noeuds.source.millegrilles_domaines_SenseursPassifs.documents'

    LIBVAL_DOCUMENT_SENSEUR = 'senseur'
    LIBVAL_DOCUMENT_NOEUD = 'noeud'
    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_VITRINE_DASHBOARD = 'vitrine.dashboard'
    LIBVAL_NOEUDS = 'noeuds'

    TRANSACTION_NOEUD_ID = 'noeud_id'
    TRANSACTION_ID_SENSEUR = 'uuid_senseur'
    TRANSACTION_DATE_LECTURE = 'timestamp'
    TRANSACTION_LOCATION = 'location'
    TRANSACTION_DOMAINE_LECTURE = '%s.lecture' % DOMAINE_NOM
    TRANSACTION_MAJ_SENSEUR = '%s.majSenseur' % DOMAINE_NOM
    TRANSACTION_MAJ_NOEUD = '%s.majNoeud' % DOMAINE_NOM
    TRANSACTION_DOMAINE_CHANG_ATTRIBUT_SENSEUR = '%s.changementAttributSenseur' % DOMAINE_NOM
    TRANSACTION_DOMAINE_SUPPRESSION_SENSEUR = '%s.suppressionSenseur' % DOMAINE_NOM
    TRANSACTION_DOMAINE_GENERER_RAPPORT = '%s.genererRapport' % DOMAINE_NOM
    SENSEUR_REGLES_NOTIFICATIONS = 'regles_notifications'

    REQUETE_VITRINE_DASHBOARD = '%s.dashboard' % DOMAINE_NOM
    REQUETE_LISTE_NOEUDS = 'listeNoeuds'
    REQUETE_LISTE_SENSEURS_NOEUD = 'listeSenseursPourNoeud'
    REQUETE_AFFICHAGE_LCD_NOEUD = 'affichageLcdNoeud'

    COMMANDE_RAPPORT_HEBDOMADAIRE = '%s.rapportHebdomadaire' % DOMAINE_NOM
    COMMANDE_RAPPORT_ANNUEL = '%s.rapportAnnuel' % DOMAINE_NOM
    COMMANDE_DECLENCHER_RAPPORTS = '%s.declencherRapports' % DOMAINE_NOM

    EVENEMENT_DOMAINE_LECTURE = '%s.lecture' % DOMAINE_NOM
    EVENEMENT_DOMAINE_LECTURE_CONFIRMEE = '%s.lectureConfirmee' % DOMAINE_NOM

    EVENEMENT_MAJ_SENSEUR_CONFIRMEE = '%s.majSenseurConfirmee' % DOMAINE_NOM
    EVENEMENT_MAJ_NOEUD_CONFIRMEE = '%s.majNoeudConfirmee' % DOMAINE_NOM

    EVENEMENT_MAJ_HORAIRE = '%s.MAJHoraire' % DOMAINE_NOM
    EVENEMENT_MAJ_QUOTIDIENNE = '%s.MAJQuotidienne' % DOMAINE_NOM

    DOCUMENT_DEFAUT_CONFIGURATION = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
        TRANSACTION_MESSAGE_LIBELLE_VERSION: TRANSACTION_MESSAGE_LIBELLE_VERSION_6
    }

    DOCUMENT_DEFAUT_VITRINE_DASHBOARD = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_VITRINE_DASHBOARD,
        LIBVAL_NOEUDS: dict(),
    }


# Constantes pour le domaine Backup
class ConstantesBackup:

    DOMAINE_NOM = 'Backup'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_RAPPORTS_NOM = '%s/rapports' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_NOEUDS_NOM = '%s.noeuds' % DOMAINE_NOM
    QUEUE_INTER_NOM = '%s.inter' % DOMAINE_NOM

    TRANSACTION_CATALOGUE_HORAIRE = '%s.catalogueHoraire' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_HORAIRE_HACHAGE = '%s.catalogueHoraireHachage' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_HORAIRE_HACHAGE_ENTETE = '%s.catalogueHoraireHachageEntete' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_QUOTIDIEN = '%s.catalogueQuotidienFinaliser' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_ANNUEL = '%s.catalogueAnnuelFinaliser' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_APPLICATION = '%s.catalogueApplication' % DOMAINE_NOM

    TRANSACTION_ARCHIVE_QUOTIDIENNE_INFO = '%s.archiveQuotidienneInfo' % DOMAINE_NOM
    TRANSACTION_ARCHIVE_ANNUELLE_INFO = '%s.archiveAnnuelleInfo' % DOMAINE_NOM

    TRANSACTION_RAPPORT_RESTAURATION = '%s.rapportRestauration' % DOMAINE_NOM

    COMMANDE_BACKUP_QUOTIDIEN = 'commande.backup.genererBackupQuotidien'
    COMMANDE_BACKUP_MENSUEL = 'commande.backup.genererBackupMensuel'
    COMMANDE_BACKUP_ANNUEL = 'commande.backup.genererBackupAnnuel'

    COMMANDE_BACKUP_DECLENCHER_HORAIRE_GLOBAL = 'commande.global.declencherBackupHoraire'
    COMMANDE_BACKUP_DECLENCHER_SNAPSHOT_GLOBAL = 'commande.global.declencherBackupSnapshot'
    COMMANDE_BACKUP_RESET_GLOBAL = 'commande.global.resetBackup'
    COMMANDE_BACKUP_DECLENCHER_HORAIRE = 'commande._DOMAINE_.declencherBackupHoraire'
    COMMANDE_BACKUP_DECLENCHER_QUOTIDIEN = 'commande._DOMAINE_.declencherBackupQuotidien'
    COMMANDE_BACKUP_DECLENCHER_ANNUEL = 'commande._DOMAINE_.declencherBackupAnnuel'
    COMMANDE_BACKUP_DECLENCHER_SNAPSHOT = 'commande._DOMAINE_.declencherBackupSnapshot'

    COMMANDE_BACKUP_PREPARER_RESTAURATION = 'preparerStagingRestauration'
    COMMANDE_BACKUP_RESTAURER_TRANSACTIONS = 'restaurerTransactions'

    REQUETE_BACKUP_DERNIERHORAIRE = '%s.backupDernierHoraire' % DOMAINE_NOM

    EVENEMENT_BACKUP = 'evenement.backup.backupTransaction'
    EVENEMENT_BACKUP_APPLICATION = 'evenement.backup.backupApplication'
    EVENEMENT_RESTAURATION_APPLICATION = 'evenement.backup.restaurationApplication'

    EVENEMENT_BACKUP_MAJ = 'backupMaj'
    EVENEMENT_BACKUP_HORAIRE_DEBUT = 'backupHoraireDebut'
    EVENEMENT_BACKUP_HORAIRE_TERMINE = 'backupHoraireTermine'
    EVENEMENT_BACKUP_QUOTIDIEN_DEBUT = 'backupQuotidienDebut'
    EVENEMENT_BACKUP_QUOTIDIEN_TERMINE = 'backupQuotidienTermine'
    EVENEMENT_BACKUP_ANNUEL_DEBUT = 'backupAnnuelDebut'
    EVENEMENT_BACKUP_ANNUEL_TERMINE = 'backupAnnuelTermine'
    EVENEMENT_BACKUP_COMPLET_TERMINE = 'backupTermine'

    EVENEMENT_BACKUP_SNAPSHOT_DEBUT = 'backupSnapshotDebut'
    EVENEMENT_BACKUP_SNAPSHOT_CATALOGUE_PRET = 'backupSnapshotCataloguePret'
    EVENEMENT_BACKUP_SNAPSHOT_UPLOAD_CONFIRME = 'backupSnapshotUploadConfirme'
    EVENEMENT_BACKUP_SNAPSHOT_TERMINE = 'backupSnapshotTermine'

    EVENEMENT_BACKUP_APPLICATION_DEBUT = 'backupApplicationDebut'
    EVENEMENT_BACKUP_APPLICATION_CATALOGUE_PRET = 'backupApplicationCataloguePret'
    EVENEMENT_BACKUP_APPLICATION_UPLOAD_CONFIRME = 'backupApplicationUploadConfirme'
    EVENEMENT_BACKUP_APPLICATION_TERMINE = 'backupApplicationTermine'
    EVENEMENT_BACKUP_APPLICATIONS_TERMINE = 'backupApplicationsTermine'

    EVENEMENT_RESTAURATION_TERMINEE = 'restaurationTerminee'

    LIBVAL_CATALOGUE_HORAIRE = 'catalogue.horaire'
    LIBVAL_CATALOGUE_QUOTIDIEN = 'catalogue.quotidien'
    LIBVAL_CATALOGUE_ANNUEL = 'catalogue.annuel'
    LIBVAL_CATALOGUE_APPLICATIONS = 'catalogue.applications'
    LIBVAL_RAPPORT_RESTAURATION = 'rapportRestauration'
    LIBVAL_RAPPORT_BACKUP = 'rapportBackup'
    LIBVAL_RAPPORT_VERIFICATION = 'rapportVerification'

    LIBELLE_SECURITE = 'securite'
    LIBELLE_HEURE = 'heure'
    LIBELLE_JOUR = 'jour'
    LIBELLE_MOIS = 'mois'
    LIBELLE_ANNEE = 'annee'
    LIBELLE_DOMAINE = 'domaine'
    LIBELLE_APPLICATION = 'application'
    LIBELLE_SOUS_DOMAINE = 'sous_domaine'
    LIBELLE_CERTS_RACINE = 'certificats_racine'
    LIBELLE_CERTS_INTERMEDIAIRES = 'certificats_intermediaires'
    LIBELLE_CERTS = 'certificats'
    LIBELLE_CERTS_PEM = 'certificats_pem'
    LIBELLE_CERTS_CHAINE_CATALOGUE = 'certificats_chaine_catalogue'
    LIBELLE_FUUID_GROSFICHIERS = 'fuuid_grosfichiers'
    LIBELLE_FICHIERS_HORAIRE = 'fichiers_horaire'
    LIBELLE_FICHIERS_QUOTIDIEN = 'fichiers_quotidien'
    LIBELLE_FICHIERS_MENSUEL = 'fichiers_mensuel'
    LIBELLE_APPLICATIONS = 'applications'
    LIBELLE_INFO_HORAIRE = 'info_horaire'
    LIBELLE_TRANSACTIONS_HACHAGE = 'transactions_hachage'
    LIBELLE_TRANSACTIONS_NOMFICHIER = 'transactions_nomfichier'
    LIBELLE_CATALOGUE_HACHAGE = 'catalogue_hachage'
    LIBELLE_CATALOGUE_NOMFICHIER = 'catalogue_nomfichier'
    LIBELLE_CATALOGUES = 'catalogues'
    LIBELLE_FICHIERS_TRANSACTIONS = 'fichiers_transactions'
    LIBELLE_DIRTY_FLAG = 'dirty_flag'
    LIBELLE_BACKUP_PRECEDENT = 'backup_precedent'
    LIBELLE_HACHAGE_ENTETE = 'hachage_entete'
    LIBELLE_TRANSACTIONS = 'transactions'
    LIBELLE_HACHAGE_BYTES = 'hachage_bytes'

    LIBELLE_ARCHIVE_NOMFICHIER = 'archive_nomfichier'
    LIBELLE_ARCHIVE_HACHAGE = 'archive_hachage'

    CHAMP_UUID_RAPPORT = 'uuid_rapport'


class ConstantesHebergement:

    DOMAINE_NOM = 'Hebergement'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM
    ROUTING_CHANGEMENTS = 'noeuds.source.millegrilles_domaines_Hebergement.documents'

    LIBVAL_MILLEGRILLE_HEBERGEE = 'millegrille.hebergee'

    CHAMP_HEBERGEMENT_ETAT = 'etat'

    VALEUR_HEBERGEMENT_ACTIF = 'actif'
    VALEUR_HEBERGEMENT_INACTIF = 'inactif'

    REQUETE_MILLEGRILLES_ACTIVES = '%s.requeteMilleGrillesActives' % DOMAINE_NOM
    REQUETE_MILLEGRILLES_HEBERGEES = '%s.requeteMilleGrillesHebergees' % DOMAINE_NOM

    TRANSACTION_NOUVEAU_IDMG = '%s.nouveauIdmg' % DOMAINE_NOM
    TRANSACTION_ACTIVER_MILLEGRILLE_HEBERGEE = '%s.activerMilleGrilleHebergee' % DOMAINE_NOM
    TRANSACTION_DESACTIVER_MILLEGRILLE_HEBERGEE = '%s.desactiverMilleGrilleHebergee' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_MILLEGRILLE_HEBERGEE = '%s.supprimerMilleGrilleHebergee' % DOMAINE_NOM

    COMMANDE_CREER_MILLEGRILLE_HEBERGEE = '%s.creerMilleGrilleHebergee' % DOMAINE_NOM

    CORRELATION_MILLEGRILLES_ACTIVES = 'millegrilles_actives'
    CORRELATION_TROUSSEAU_MODULE = 'trousseau_module'


class ConstantesMaitreDesComptes:

    DOMAINE_NOM = 'MaitreDesComptes'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM

    LIBVAL_USAGER = 'usager'
    LIBVAL_PROPRIETAIRE = 'proprietaire'

    CHAMP_NOM_USAGER = 'nomUsager'
    CHAMP_MOTDEPASSE = 'motdepasse'
    CHAMP_CLE = 'cle'
    CHAMP_CLES_U2F = 'u2f'
    CHAMP_RESET_CLES = 'reset_cles'
    CHAMP_EST_PROPRIETAIRE = 'est_proprietaire'
    CHAMP_CHAINE_CERTIFICAT = 'chaine_certificats'
    CHAMP_RESET_CERTIFICATS = 'reset_certificats'
    CHAMP_CERTIFICATS = 'certificats'
    CHAMP_IDMGS = 'idmgs'
    CHAMP_IDMG_COMPTE = 'idmgCompte'
    CHAMP_TOTP = 'totp'

    REQUETE_CHARGER_USAGER = 'chargerUsager'
    REQUETE_INFO_PROPRIETAIRE = 'infoProprietaire'

    TRANSACTION_INSCRIRE_PROPRIETAIRE = 'inscrireProprietaire'
    TRANSACTION_INSCRIRE_USAGER = 'inscrireUsager'
    TRANSACTION_MAJ_MOTDEPASSE = 'majMotdepasse'
    TRANSACTION_MAJ_CLEUSAGERPRIVE = 'majCleUsagerPrive'
    TRANSACTION_SUPPRESSION_MOTDEPASSE = 'suppressionMotdepasse'
    TRANSACTION_AJOUTER_CLE = 'ajouterCle'
    TRANSACTION_SUPPRIMER_CLES = 'supprimerCles'
    TRANSACTION_SUPPRIMER_USAGER = 'supprimerUsager'
    TRANSACTION_ASSOCIER_CERTIFICAT = 'associerCertificat'
    TRANSACTION_AJOUTER_NAVIGATEUR = 'ajouterNavigateur'
    TRANSACTION_MAJ_USAGER_TOTP = 'majUsagerTotp'


class ConstantesMessagerie:

    DOMAINE_NOM = 'Messagerie'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_MESSAGES_USAGERS_NOM = '%s/messagesUsager' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_COMPTES_USAGERS_NOM = '%s/comptesUsager' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_ROUTING_MAJ_MESSAGES = 'evenement.%s.messages' % DOMAINE_NOM
    QUEUE_ROUTING_MAJ_COMPTES = 'evenement.%s.comptes' % DOMAINE_NOM

    REQUETE_CHARGER_COMPTE = 'chargerCompte'
    REQUETE_SOMMAIRE_MESSAGES_PAR_IDMG = 'sommaireMessagesParIdmg'
    REQUETE_MESSAGES_USAGER_PAR_SOURCE = 'messagesUsagerParSource'

    TRANSACTION_INSCRIRE_COMPTE = 'inscrireCompte'
    TRANSACTION_AJOUTER_IDMGS_COMPTE = 'ajouterIdmgsCompte'
    TRANSACTION_ENVOYER_MESSAGE = 'envoyerMessage'
    TRANSACTION_MARQUER_MESSAGE_LU = 'marquerMessageLu'
    TRANSACTION_SUPPRIMER_MESSAGE = 'supprimerMessage'
    TRANSACTION_MODIFIER_CONTACT = 'modifierContact'

    LIBVAL_COMPTE_USAGER = 'compteUsager'
    LIBVAL_MESSAGE_INSTANTANNE = 'message.instantanne'
    LIBVAL_MESSAGE_COURRIEL = 'message.courriel'

    CHAMP_NOM_USAGER = 'nom_usager'
    CHAMP_IDMG_SOURCE = 'idmg_source'
    CHAMP_IDMG_DESTINATION = 'idmg_destination'
    CHAMP_DATE_ENVOI = 'date_envoi'
    CHAMP_DATE_LECTURE = 'date_lecture'
    CHAMP_IDMGS = 'idmgs'
    CHAMP_IDMGS_SOURCE = 'idmgs_source'
    CHAMP_IDMGS_DESTINATION = 'idmgs_destination'
    CHAMP_CONTENU = 'contenu'
    CHAMP_MESSAGE = 'message'
    CHAMP_SUJET = 'sujet'
    CHAMP_CONTACT = 'contact'
    CHAMP_CONTACTS = 'contacts'
    CHAMP_NOM_CONTACT = 'nom_contact'
    CHAMP_NOM_USAGER_CONTACT = 'nom_usager_contact'
    CHAMP_UUID_CONTACT = 'uuid_contact'
    CHAMP_SUPPRIMER = 'supprimer'


class ConstantesHebergementTransactions:

    pass

class CommandesSurRelai:
    """
    Commandes qui sont supportes dans l'espace relai pour permettre aux connecteurs d'interagir
    """

    HEADER_COMMANDE = 'connecteur_commande'
    HEADER_TRANSFERT_INTER_COMPLETE = 'transfert_inter_complete'
    HEADER_IDMG_ORIGINE = 'idmg_origine'

    # Une annonce est placee sur l'echange prive avec le routing key definit ci-bas
    BINDING_ANNONCES = 'annonce.#'
    ANNONCE_CONNEXION = 'annonce.connexion'  # Evenement de connexion sur echange prive
    ANNONCE_DECONNEXION = 'annonce.deconnexion'  # Evenement de deconnexion sur echange prive
    ANNONCE_RECHERCHE_CERTIFICAT = 'annonce.requete.certificat'  # Requete d'un certificat par fingerprint
    ANNONCE_PRESENCE = 'annonce.presence'  # Annonce la presence d'une millegrille (regulierement)

    # Le type de commande est place dans le header 'connecteur_commande' du message

    # -- Commandes sans inscription --
    BINDING_COMMANDES = 'commande.#'
    COMMANDE_DEMANDE_INSCRIPTION = 'commande.inscription'  # Transmet une demande d'inscription a une MilleGrille tierce

    # Transmet une demande de confirmation de presence a un connecteur de MilleGrille tierce qui repond par pong
    COMMANDE_PING = 'commande.ping'

    # -- Commandes avec inscription --
    # Une commande est dirigee vers une MilleGrille tierce specifique sur un echange direct (e.g. echange par defaut)
    COMMANDE_CONNEXION = 'commande.connexion'  # Demande de connexion vers une millegrille tierce presente sur relai
    COMMANDE_DECONNEXION = 'commande.deconnexion'  # Deconnexion d'une millegrille tierce presente sur relai
    COMMANDE_PRESENCE = 'commande.presence'  # Utilise pour indiquer presence/activite a un tiers (regulierement)
    COMMANDE_DEMANDE_FICHE = 'commande.demandeFiche'  # Demande la fiche privee d'une MilleGrille tierce

    # Commandes de relai de messages
    # Le contenu doit etre contre-signee par le certificat de connecteur pour etre admises
    COMMANDE_MESSAGE_RELAI = 'commande.message.relai'  # Relai message de la MilleGrille d'origine


class ConstantesGenerateurCertificat:

    ROLE_MQ = 'mq'
    ROLE_MONGO = 'mongo'
    ROLE_DEPLOYEUR = 'deployeur'
    ROLE_MAITREDESCLES = 'maitrecles'
    ROLE_TRANSACTIONS = 'transaction'
    ROLE_CEDULEUR = 'ceduleur'
    ROLE_DOMAINES = 'domaines'
    ROLE_FICHIERS = 'fichiers'
    ROLE_GROS_FICHIERS = 'GrosFichiers'
    ROLE_MONGOEXPRESS = 'mongoxp'
    ROLE_NAVIGATEUR = 'navigateur'
    ROLE_WEB_PROTEGE = 'web_protege'
    ROLE_WEB_PRIVE = 'web_prive'
    ROLE_WEB_PUBLIC = 'web_public'
    ROLE_NGINX = 'nginx'
    ROLE_VITRINE = 'vitrine'
    ROLE_CONNECTEUR = 'connecteur'
    ROLE_MONITOR = 'monitor'
    ROLE_MONITOR_DEPENDANT = 'monitor_dependant'
    ROLE_CONNECTEUR_TIERS = 'tiers'
    ROLE_BACKUP = 'backup'
    ROLE_NOEUD_PRIVE = 'prive'
    ROLE_NOEUD_PUBLIC = 'public'
    ROLE_APPLICATION_PRIVEE = 'application'
    ROLE_HEBERGEMENT = 'hebergement'
    ROLE_HEBERGEMENT_TRANSACTIONS = 'heb_transaction'
    ROLE_HEBERGEMENT_DOMAINES = 'heb_domaines'
    ROLE_HEBERGEMENT_MAITREDESCLES = 'heb_maitrecles'
    ROLE_HEBERGEMENT_FICHIERS = 'heb_fichiers'
    ROLE_HEBERGEMENT_COUPDOEIL = 'heb_coupdoeil'


class ConstantesServiceMonitor:

    ETAT_SYSTEME_INITIAL = '1.initial'
    ETAT_SYSTEME_CERTSMILLEGRILLE_PRET = '2.certs_millegrille_pret'
    ETAT_SYSTEME_MIDDLEWARE_PRET = '3.middleware_pret'
    ETAT_SYSTEME_MODULES_PRET = '4.modules_prets'
    ETAT_SYSTEME_ACTIF = '5.systeme_actif'
    ETAT_SYSTEME_FERMETURE = '6.systeme_fermeture'

    EXIT_REDEMARRAGE = 2

    DOCKER_LIBVAL_CONFIG_IDMG = 'millegrille.idmg'
    DOCKER_LIBVAL_CONFIG_SECURITE = 'millegrille.securite'
    DOCKER_LIBVAL_CONFIG = 'millegrille.configuration'

    MODULE_ACME = 'acme'
    MODULE_MQ = 'mq'
    MODULE_MONGO = 'mongo'
    MODULE_TRANSACTION = 'transaction'
    MODULE_MAITREDESCLES = 'maitrecles'
    MODULE_CEDULEUR = 'ceduleur'
    MODULE_CONSIGNATIONFICHIERS = 'fichiers'
    # MODULE_COUPDOEIL = 'coupdoeilreact'
    # MODULE_TRANSMISSION = 'transmission'
    # MODULE_DOMAINES = 'domaines'
    MODULE_PRINCIPAL = 'principal'
    MODULE_DOMAINES_DYNAMIQUES = 'domaines_dynamiques'
    MODULE_NGINX = 'nginx'
    MODULE_WEB_PROTEGE = 'web_protege'
    MODULE_WEB = 'web'
    MODULE_PYTHON = 'mg-python'
    MODULE_MONGOEXPRESS = 'mongoxp'
    # MODULE_HEBERGEMENT_TRANSACTIONS = 'heb_transaction'
    # MODULE_HEBERGEMENT_DOMAINES = 'heb_domaines'
    # MODULE_HEBERGEMENT_MAITREDESCLES = 'heb_maitrecles'
    # MODULE_HEBERGEMENT_COUPDOEIL = 'heb_coupdoeil'
    # MODULE_HEBERGEMENT_FICHIERS = 'heb_fichiers'

    FICHIER_MONGO_MOTDEPASSE = 'passwd.mongo.txt'
    FICHIER_MONGOXPWEB_MOTDEPASSE = 'passwd.mongoxpweb.txt'
    FICHIER_MQ_MOTDEPASSE = 'passwd.mq.txt'
    PKI_MONITOR_KEY = 'pki.monitor.key'
    PKI_MONITOR_CERT = 'pki.monitor.cert'

    CERT_SUFFIX = '.cert'
    CHAIN_SUFFIX = '.chain'
    KEY_SUFFIX = '.key'
    PASSWD_SUFFIX = '.passwd'

    DOCKER_CONFIG_NAME_MILLEGRILLE = 'pki.millegrille'
    DOCKER_CONFIG_NAME_INTERMEDIAIRE = 'pki.intermediaire'
    DOCKER_CONFIG_NAME_MONITOR = 'pki.monitor'
    DOCKER_CONFIG_NAME_MONITOR_DEPENDANT = 'pki.monitor_dependant'

    DOCKER_CONFIG_MILLEGRILLE_CERT = DOCKER_CONFIG_NAME_MILLEGRILLE + CERT_SUFFIX
    DOCKER_CONFIG_MILLEGRILLE_KEY = DOCKER_CONFIG_NAME_MILLEGRILLE + KEY_SUFFIX
    DOCKER_CONFIG_MILLEGRILLE_PASSWD = DOCKER_CONFIG_NAME_MILLEGRILLE + PASSWD_SUFFIX
    DOCKER_CONFIG_INTERMEDIAIRE_CERT = DOCKER_CONFIG_NAME_INTERMEDIAIRE + CERT_SUFFIX
    DOCKER_CONFIG_INTERMEDIAIRE_CHAIN = DOCKER_CONFIG_NAME_INTERMEDIAIRE + CHAIN_SUFFIX
    DOCKER_CONFIG_INTERMEDIAIRE_KEY = DOCKER_CONFIG_NAME_INTERMEDIAIRE + KEY_SUFFIX
    DOCKER_CONFIG_INTERMEDIAIRE_PASSWD = DOCKER_CONFIG_NAME_INTERMEDIAIRE + PASSWD_SUFFIX
    DOCKER_CONFIG_MONITOR_CERT = DOCKER_CONFIG_NAME_MONITOR + CERT_SUFFIX
    DOCKER_CONFIG_MONITOR_KEY = DOCKER_CONFIG_NAME_MONITOR + KEY_SUFFIX
    DOCKER_CONFIG_MONITOR_DEPENDANT_KEY = DOCKER_CONFIG_NAME_MONITOR_DEPENDANT + KEY_SUFFIX
    DOCKER_CONFIG_NOEUD_ID = 'millegrille.noeud_id'

    COMMANDE_CONFIGURER_DOMAINE = 'configurerDomaine'
    COMMANDE_CONFIGURER_IDMG = 'configurerIdmg'
    COMMANDE_INSTALLER_NOEUD = 'installerNoeud'
    COMMANDE_CONFIGURER_MQ = 'configurerMq'

    COMMANDE_ACTIVER_HEBERGEMENT = 'activerHebergement'
    COMMANDE_DESACTIVER_HEBERGEMENT = 'desactiverHebergement'
    COMMANDE_AJOUTER_COMPTE = 'ajouterCompte'

    COMMANDE_INSTALLER_APPLICATION = 'installerApplication'
    COMMANDE_SUPPRIMER_APPLICATION = 'supprimerApplication'
    COMMANDE_BACKUP_APPLICATION = 'backupApplication'
    COMMANDE_RESTORE_APPLICATION = 'restoreApplication'
    COMMANDE_TRANSMETTRE_CATALOGUES = 'transmettreCatalogues'
    COMMANDE_CONFIGURER_APPLICATION = 'configurerApplication'
    COMMANDE_DEMARRER_APPLICATION = 'demarrerApplication'
    COMMANDE_SIGNER_NAVIGATEUR = 'signerNavigateur'
    COMMANDE_SIGNER_NOEUD = 'signerNoeud'

    COMMANDE_REQUETE_CONFIG_APPLICATION = 'requeteConfigurationApplication'

    # Commande de l'acteur systeme du noeud
    COMMANDE_ACTEUR_GET_INFORMATION_NOEUD = 'acteur.getInformationNoeud'
    COMMANDE_ACTEUR_REPONSE_MDNS = 'acteur.reponseMdns'

    CORRELATION_HEBERGEMENT_LISTE = 'hebergementListeActives'
    CORRELATION_LISTE_COMPTES_NOEUDS = 'listeComptesNoeuds'
    CORRELATION_CERTIFICAT_SIGNE = 'certificatSigne'
    CORRELATION_RENOUVELLEMENT_CERTIFICAT = 'renouvellementCertificat'

    GROUP_MILLEGRILLES = 'millegrilles'
    GROUP_MILLEGRILLES_GID = 980

    USER_MONITOR = 'mg_monitor'
    USER_MONITOR_UID = 980
    USER_MAITREDESCLES = 'mg_maitredescles'
    USER_MAITREDESCLES_UID = 981
    USER_PYTHON = 'mg_python'
    USER_PYTHON_UID = 982
    USER_MONGO = 'mg_mongo'
    USER_MONGO_UID = 983
    USER_PUBLIC = 'mg_public'
    USER_PUBLIC_UID = 984
    USER_FICHIERS = 'mg_fichiers'
    USER_FICHIERS_UID = 985


class ConstantesTopologie:

    DOMAINE_NOM = 'Topologie'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM

    LIBVAL_DOMAINE = 'domaine'
    LIBVAL_NOEUD = 'noeud'

    TRANSACTION_DOMAINE = '%s.domaine' % DOMAINE_NOM
    TRANSACTION_MONITOR = '%s.monitor' % DOMAINE_NOM
    TRANSACTION_AJOUTER_DOMAINE_DYNAMIQUE = '%s.ajouterDomaineDynamique' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_DOMAINE_DYNAMIQUE = '%s.supprimerDomaineDynamique' % DOMAINE_NOM
    TRANSACTION_CONFIGURER_CONSIGNATION_WEB = 'configurerConsignationWeb'

    EVENEMENT_PRESENCE_DOMAINE = 'evenement.presence.domaine'
    EVENEMENT_PRESENCE_MONITOR = 'evenement.presence.monitor'

    REQUETE_LISTE_DOMAINES = '%s.listeDomaines' % DOMAINE_NOM
    REQUETE_LISTE_NOEUDS = '%s.listeNoeuds' % DOMAINE_NOM
    REQUETE_INFO_DOMAINE = '%s.infoDomaine' % DOMAINE_NOM
    REQUETE_INFO_NOEUD = '%s.infoNoeud' % DOMAINE_NOM
    REQUETE_LISTE_APPLICATIONS_DEPLOYEES = '%s.listeApplicationsDeployees' % DOMAINE_NOM
    REQUETE_PERMISSION = 'permissionDechiffrage'
    REQUETE_LISTE_NOEUDS_AWSS3 = 'listerNoeudsAWSS3'

    CHAMP_NOEUDID = 'noeud_id'
    CHAMP_CONSIGNATION_WEB = 'consignation_web'
    CHAMP_CONSIGNATION_WEB_MODE = 'modeConsignation'
    CHAMP_AWSS3_CREDENTIALS_ACCESSID = 'credentialsAccessKeyId'
    CHAMP_AWSS3_CREDENTIALS_ACCESSKEY = 'credentialsSecretAccessKey'
    CHAMP_AWSS3_CREDENTIALS_REGION = 'credentialsRegion'
    CHAMP_AWSS3_BUCKET_REGION = 'bucketRegion'
    CHAMP_AWSS3_BUCKET_NAME = 'bucketName'
    CHAMP_AWSS3_BUCKET_DIRFICHIER = 'bucketDirfichier'

    VALEUR_AWSS3_CONSIGNATION_WEB_NGINX = 'cachenginx'
    VALEUR_AWSS3_CONSIGNATION_WEB_AWSS3 = 'awss3'

class ConstantesPublication:

    DOMAINE_NOM = 'Publication'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_SITES_NOM = '%s/sites' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_POSTS_NOM = '%s/posts' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM

    DOCUMENT_DEFAUT = {
        DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
        TRANSACTION_MESSAGE_LIBELLE_VERSION: 6,
    }

    LIBVAL_SITE_CONFIG = 'siteconfig'
    LIBVAL_ACCUEIL = 'accueil'
    LIBVAL_POST = 'post'

    REQUETE_CONFIGURATION_SITE = 'configurationSite'
    REQUETE_SITES_POUR_NOEUD = 'sitesPourNoeud'
    REQUETE_LISTE_SITES = 'listeSites'
    REQUETE_POSTS = 'posts'

    TRANSACTION_MAJ_SITE = 'majSite'
    TRANSACTION_MAJ_POST = 'majPost'

    EVENEMENT_CONFIRMATION_MAJ_SITE = 'confirmationMajSite'
    EVENEMENT_CONFIRMATION_MAJ_POST = 'confirmationMajPost'

    CHAMP_SITE_ID = 'site_id'
    CHAMP_POST_ID = 'post_id'
    CHAMP_NOM_SITE = 'nom_site'
    CHAMP_LANGUAGES = 'languages'
    CHAMP_TITRE = 'titre'
    CHAMP_NOEUDS_URLS = 'noeuds_urls'
    CHAMP_URLS = 'urls'
    CHAMP_FICHIERS = 'fichiers'
    CHAMP_ALBUMS = 'albums'
    CHAMP_POST_ROWS = 'post_rows'
    CHAMP_TOUTES_COLLECTIONS = 'toutes_collections'
    CHAMP_POST_IDS = 'post_ids'
    CHAMP_HTML = 'html'
    CHAMP_DATE_POST = 'date_post'


class ConstantesCatalogueApplications:

    DOMAINE_NOM = 'CatalogueApplications'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM

    LIBVAL_DOMAINE = 'domaine'
    LIBVAL_APPLICATION = 'application'

    TRANSACTION_MAJ_DOMAINE = '%s.majDomaine' % DOMAINE_NOM
    TRANSACTION_MAJ_APPLICATION = '%s.majApplication' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_APPLICATION = '%s.catalogueApplication' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_DOMAINE = '%s.catalogueDomaine' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_APPLICATIONS = '%s.catalogueApplications' % DOMAINE_NOM
    TRANSACTION_CATALOGUE_DOMAINES = '%s.catalogueDomaines' % DOMAINE_NOM

    REQUETE_LISTE_DOMAINES = '%s.listeDomaines' % DOMAINE_NOM
    REQUETE_LISTE_APPLICATIONS = '%s.listeApplications' % DOMAINE_NOM
    REQUETE_INFO_DOMAINE = '%s.infoDomaine' % DOMAINE_NOM
    REQUETE_INFO_APPLICATION = '%s.infoApplication' % DOMAINE_NOM


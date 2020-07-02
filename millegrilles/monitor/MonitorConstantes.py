from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat

SERVICEMONITOR_LOGGING_FORMAT = '%(threadName)s:%(levelname)s:%(message)s'
PATH_FIFO = '/var/opt/millegrilles/monitor.socket'
PATH_PKI = '/var/opt/millegrilles/pki'
DOCKER_LABEL_TIME = '%Y%m%d%H%M%S'


DICT_MODULES = {
    ConstantesServiceMonitor.MODULE_MQ: {
        'nom': ConstantesServiceMonitor.MODULE_MQ,
        'role': ConstantesGenerateurCertificat.ROLE_MQ,
    },
    ConstantesServiceMonitor.MODULE_MONGO: {
        'nom': ConstantesServiceMonitor.MODULE_MONGO,
        'role': ConstantesGenerateurCertificat.ROLE_MONGO,
    },
    ConstantesServiceMonitor.MODULE_TRANSACTION: {
        'nom': ConstantesServiceMonitor.MODULE_PYTHON,
        'role': ConstantesGenerateurCertificat.ROLE_TRANSACTIONS,
    },
    ConstantesServiceMonitor.MODULE_MAITREDESCLES: {
        'nom': ConstantesServiceMonitor.MODULE_PYTHON,
        'role': ConstantesGenerateurCertificat.ROLE_MAITREDESCLES,
    },
    ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS: {
        'nom': ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS,
        'role': ConstantesGenerateurCertificat.ROLE_FICHIERS,
    },
    ConstantesServiceMonitor.MODULE_WEB_PROTEGE: {
        'nom': ConstantesServiceMonitor.MODULE_WEB,  # Module web generique
        'role': ConstantesGenerateurCertificat.ROLE_WEB_PROTEGE,
    },
    ConstantesServiceMonitor.MODULE_NGINX: {
        'nom': ConstantesServiceMonitor.MODULE_NGINX,
        'role': ConstantesGenerateurCertificat.ROLE_NGINX,
    },
    ConstantesServiceMonitor.MODULE_PRINCIPAL: {
        'nom': ConstantesServiceMonitor.MODULE_PYTHON,
        'role': ConstantesGenerateurCertificat.ROLE_DOMAINES,
    },
    ConstantesServiceMonitor.MODULE_DOMAINES_DYNAMIQUES: {
        'nom': ConstantesServiceMonitor.MODULE_PYTHON,
        'role': ConstantesGenerateurCertificat.ROLE_DOMAINES,
    },
    ConstantesServiceMonitor.MODULE_MONGOEXPRESS: {
        'nom': ConstantesServiceMonitor.MODULE_MONGOEXPRESS,
        'role': ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS,
    },
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_TRANSACTIONS: {
    #     'nom': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'role': ConstantesGenerateurCertificat.ROLE_HEBERGEMENT_TRANSACTIONS,
    # },
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_DOMAINES: {
    #     'nom': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'role': ConstantesGenerateurCertificat.ROLE_HEBERGEMENT_DOMAINES,
    # },
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_MAITREDESCLES: {
    #     'nom': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'role': ConstantesGenerateurCertificat.ROLE_HEBERGEMENT_MAITREDESCLES,
    # },
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_COUPDOEIL: {
    #     'nom': ConstantesServiceMonitor.MODULE_COUPDOEIL,
    #     'role': ConstantesGenerateurCertificat.ROLE_HEBERGEMENT_COUPDOEIL,
    # },
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_FICHIERS: {
    #     'nom': ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS,
    #     'role': ConstantesGenerateurCertificat.ROLE_HEBERGEMENT_FICHIERS,
    # },
}

# Liste de modules requis. L'ordre est important
MODULES_REQUIS_PRIMAIRE = [
    ConstantesServiceMonitor.MODULE_MQ,
    ConstantesServiceMonitor.MODULE_MONGO,
    ConstantesServiceMonitor.MODULE_TRANSACTION,
    ConstantesServiceMonitor.MODULE_MAITREDESCLES,
    ConstantesServiceMonitor.MODULE_PRINCIPAL,
    ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS,
    ConstantesServiceMonitor.MODULE_WEB_PROTEGE,
    ConstantesServiceMonitor.MODULE_NGINX,
    ConstantesServiceMonitor.MODULE_DOMAINES_DYNAMIQUES,
]

MODULES_REQUIS_DEPENDANT = [
    ConstantesServiceMonitor.MODULE_MQ,
    ConstantesServiceMonitor.MODULE_MONGO,
    ConstantesServiceMonitor.MODULE_TRANSACTION,
]

CERTIFICATS_REQUIS_DEPENDANT = [info['role'] for info in DICT_MODULES.values() if info.get('role')]

MODULES_HEBERGEMENT = [
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_TRANSACTIONS,
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_DOMAINES,
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_MAITREDESCLES,
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_COUPDOEIL,
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_FICHIERS,
]

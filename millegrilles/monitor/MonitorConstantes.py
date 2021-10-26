from typing import cast

from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat

SERVICEMONITOR_LOGGING_FORMAT = '%(threadName)s:%(levelname)s:%(message)s'
PATH_FIFO = '/var/opt/millegrilles/monitor.socket'
PATH_PKI = '/var/opt/millegrilles/pki'
DOCKER_LABEL_TIME = '%Y%m%d%H%M%S'

PATH_SECRET_DEFAUT = '/run/secrets'

DICT_MODULES_PUBLICS = {
    ConstantesServiceMonitor.MODULE_ACME: {
        'nom': ConstantesServiceMonitor.MODULE_ACME
    },
    ConstantesServiceMonitor.MODULE_NGINX_PUBLIC: {
        'nom': ConstantesServiceMonitor.MODULE_NGINX_PUBLIC,
        'nom_image': ConstantesServiceMonitor.MODULE_NGINX,
    },
}

DICT_MODULES_PRIVES = {
    ConstantesServiceMonitor.MODULE_ACME: {
        'nom': ConstantesServiceMonitor.MODULE_ACME
    },
    ConstantesServiceMonitor.MODULE_NGINX_PUBLIC: {
        'nom': ConstantesServiceMonitor.MODULE_NGINX_PUBLIC,
        'nom_image': ConstantesServiceMonitor.MODULE_NGINX,
    },
    # ConstantesServiceMonitor.MODULE_WEB_PROTEGE: {
    #     'nom': ConstantesServiceMonitor.MODULE_WEB,  # Module web generique
    #     # 'nom_image': ConstantesServiceMonitor.MODULE_WEB,
    # },
}

DICT_MODULES_PROTEGES = {
    ConstantesServiceMonitor.MODULE_ACME: {
        'nom': ConstantesServiceMonitor.MODULE_ACME,
        'nom_image': ConstantesServiceMonitor.MODULE_ACME
    },
    ConstantesServiceMonitor.MODULE_NGINX: {
        'nom': ConstantesServiceMonitor.MODULE_NGINX,
        'nom_image': ConstantesServiceMonitor.MODULE_NGINX,
        'role': ConstantesGenerateurCertificat.ROLE_NGINX,
    },
    ConstantesServiceMonitor.MODULE_MQ: {
        'nom': ConstantesServiceMonitor.MODULE_MQ,
        'nom_image': ConstantesServiceMonitor.MODULE_MQ,
        'role': ConstantesGenerateurCertificat.ROLE_MQ,
    },
    ConstantesServiceMonitor.MODULE_MONGO: {
        'nom': ConstantesServiceMonitor.MODULE_MONGO,
        'nom_image': ConstantesServiceMonitor.MODULE_MONGO,
        'role': ConstantesGenerateurCertificat.ROLE_MONGO,
    },
    # ConstantesServiceMonitor.MODULE_TRANSACTION: {
    #     'nom': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'nom_image': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'role': ConstantesGenerateurCertificat.ROLE_TRANSACTIONS,
    # },
    ConstantesServiceMonitor.MODULE_MAITREDESCLES: {
        'nom': ConstantesServiceMonitor.MODULE_MAITREDESCLES,
        'nom_image': ConstantesServiceMonitor.MODULE_MAITREDESCLES,
        'role': ConstantesGenerateurCertificat.ROLE_MAITREDESCLES,
    },
    ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS: {
        'nom': ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS,
        'nom_image': ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS,
        'role': ConstantesGenerateurCertificat.ROLE_FICHIERS,
    },
    ConstantesServiceMonitor.MODULE_WEB_PROTEGE: {
        'nom': ConstantesServiceMonitor.MODULE_WEB,  # Module web generique
        'nom_image': ConstantesServiceMonitor.MODULE_WEB,
        'role': ConstantesGenerateurCertificat.ROLE_WEB_PROTEGE,
    },
    ConstantesServiceMonitor.MODULE_WEB_COUPDOEIL: {
        'nom': ConstantesServiceMonitor.MODULE_WEB_COUPDOEIL,
        'nom_image': ConstantesServiceMonitor.MODULE_WEB_COUPDOEIL,
        'role': ConstantesGenerateurCertificat.ROLE_WEB_PROTEGE,
    },
    # ConstantesServiceMonitor.MODULE_PRINCIPAL: {
    #     'nom': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'nom_image': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'role': ConstantesGenerateurCertificat.ROLE_DOMAINES,
    # },
    ConstantesServiceMonitor.MODULE_CORE: {
        'nom': ConstantesServiceMonitor.MODULE_CORE_RUST,
        'nom_image': ConstantesServiceMonitor.MODULE_CORE_RUST,
        'role': ConstantesGenerateurCertificat.ROLE_CORE,
    },
    ConstantesServiceMonitor.MODULE_REDIS: {
        'nom': ConstantesServiceMonitor.MODULE_REDIS,
        'nom_image': ConstantesServiceMonitor.MODULE_REDIS
    },
    ConstantesServiceMonitor.MODULE_AGENT_BACKUP: {
        'nom': ConstantesServiceMonitor.MODULE_AGENT_BACKUP,
        'nom_image': ConstantesServiceMonitor.MODULE_PYTHON,
        'role': ConstantesGenerateurCertificat.ROLE_BACKUP,
    },
    ConstantesServiceMonitor.MODULE_ELASTICSEARCH: {
        'nom': ConstantesServiceMonitor.MODULE_ELASTICSEARCH,
        'nom_image': ConstantesServiceMonitor.MODULE_ELASTICSEARCH,
    },
    ConstantesServiceMonitor.MODULE_MEDIA: {
        'nom': ConstantesServiceMonitor.MODULE_MEDIA,
        'nom_image': ConstantesServiceMonitor.MODULE_MEDIA,
        'role': ConstantesGenerateurCertificat.ROLE_MEDIA,
    },
    # ConstantesServiceMonitor.MODULE_DOMAINES_DYNAMIQUES: {
    #     'nom': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'nom_image': ConstantesServiceMonitor.MODULE_PYTHON,
    #     'role': ConstantesGenerateurCertificat.ROLE_DOMAINES,
    # },
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
MODULES_REQUIS_INSTALLATION = [
    ConstantesServiceMonitor.MODULE_ACME,
    ConstantesServiceMonitor.MODULE_NGINX,
]

MODULES_REQUIS_PRIVE_PUBLIC = [
    ConstantesServiceMonitor.MODULE_ACME,
    ConstantesServiceMonitor.MODULE_NGINX_PUBLIC,
]

MODULES_REQUIS_PRIMAIRE = [
    ConstantesServiceMonitor.MODULE_ACME,
    ConstantesServiceMonitor.MODULE_NGINX,
    ConstantesServiceMonitor.MODULE_MQ,
    ConstantesServiceMonitor.MODULE_MONGO,
    # ConstantesServiceMonitor.MODULE_TRANSACTION,
    ConstantesServiceMonitor.MODULE_MAITREDESCLES,
    # ConstantesServiceMonitor.MODULE_PRINCIPAL,
    ConstantesServiceMonitor.MODULE_CORE,
    ConstantesServiceMonitor.MODULE_REDIS,
    ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS,
    ConstantesServiceMonitor.MODULE_WEB_PROTEGE,
    ConstantesServiceMonitor.MODULE_WEB_COUPDOEIL,
    ConstantesServiceMonitor.MODULE_AGENT_BACKUP,
    ConstantesServiceMonitor.MODULE_ELASTICSEARCH,
    # ConstantesServiceMonitor.MODULE_DOMAINES_DYNAMIQUES,
]

MODULES_REQUIS_DEPENDANT = [
    ConstantesServiceMonitor.MODULE_MQ,
    ConstantesServiceMonitor.MODULE_MONGO,
    ConstantesServiceMonitor.MODULE_TRANSACTION,
]

CERTIFICATS_REQUIS_DEPENDANT = [info['role'] for info in DICT_MODULES_PROTEGES.values() if info.get('role')]

MODULES_HEBERGEMENT = [
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_TRANSACTIONS,
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_DOMAINES,
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_MAITREDESCLES,
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_COUPDOEIL,
    # ConstantesServiceMonitor.MODULE_HEBERGEMENT_FICHIERS,
]


def trouver_config(config_name: str, docker_client):
    config_names = config_name.split(';')
    configs = None
    for config_name_val in config_names:
        filtre = {'name': config_name_val}
        configs = docker_client.configs.list(filters=filtre)
        if len(configs) > 0:
            break

    # Trouver la configuration la plus recente (par date). La meme date va etre utilise pour un secret, au besoin
    date_config: int = cast(int, None)
    config_retenue = None
    for config in configs:
        nom_config = config.name
        split_config = nom_config.split('.')
        if len(split_config) >= 4:
            date_config_str = split_config[-1]
            date_config_int = int(date_config_str)
            if not date_config or date_config_int > date_config:
                date_config = date_config_int
                config_retenue = config
        else:
            config_retenue = config
            break

    reponse = {
        'config_reference': {
            'config_id': config_retenue.attrs['ID'],
            'config_name': config_retenue.name,
        },
        'config': config_retenue,
    }

    if date_config:
        reponse['date'] = str(date_config)

    return reponse


class CommandeMonitor:

    def __init__(self, contenu: dict, mq_properties=None, message: dict = None):
        self.__contenu = contenu
        self.__mq_properties = mq_properties
        self.__message = message

    @property
    def contenu(self):
        return self.__contenu

    @property
    def mq_properties(self):
        return self.__mq_properties

    @property
    def nom_commande(self):
        return self.__contenu['commande']

    @property
    def message(self):
        return self.__message


class ImageNonTrouvee(Exception):

    def __init__(self, image, t=None, obj=None):
        super().__init__(t, obj)
        self.image = image


class ForcerRedemarrage(Exception):
    pass


class ExceptionExecution(Exception):

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)
        self.__resultat = kwargs['resultat']

    @property
    def resultat(self):
        return self.__resultat


class PkiCleNonTrouvee(Exception):
    pass


class GenerationCertificatNonSupporteeException(Exception):
    """
    Indique qu'il n'est pas possible de generer un certificat sur ce noeud
    """
    pass

# Configuration pour traiter les transactions

import os
import json
import logging
import ssl

from cryptography.hazmat.backends import default_backend
from cryptography.x509.name import NameOID

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.SecuritePKI import SignateurTransaction


class TransactionConfiguration:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        # Configuration de connection a RabbitMQ
        self._mq_config = {
            Constantes.CONFIG_MQ_HOST: Constantes.DEFAUT_HOSTNAME,
            Constantes.CONFIG_MQ_PORT: '5671',
            Constantes.CONFIG_MQ_HEARTBEAT: Constantes.DEFAUT_MQ_HEARTBEAT,
            Constantes.CONFIG_MQ_VIRTUAL_HOST: Constantes.DEFAUT_MQ_VIRTUAL_HOST,
            Constantes.CONFIG_QUEUE_NOUVELLES_TRANSACTIONS: Constantes.DEFAUT_QUEUE_NOUVELLES_TRANSACTIONS,
            Constantes.CONFIG_QUEUE_EVENEMENTS_TRANSACTIONS: Constantes.DEFAUT_QUEUE_EVENEMENTS_TRANSACTIONS,
            Constantes.CONFIG_QUEUE_ERREURS_TRANSACTIONS: Constantes.DEFAUT_QUEUE_ERREURS_TRANSACTIONS,
            Constantes.CONFIG_QUEUE_MGP_PROCESSUS: Constantes.DEFAUT_QUEUE_MGP_PROCESSUS,
            Constantes.CONFIG_QUEUE_ERREURS_PROCESSUS: Constantes.DEFAUT_QUEUE_ERREURS_PROCESSUS,
            Constantes.CONFIG_QUEUE_GENERATEUR_DOCUMENTS: Constantes.DEFAUT_QUEUE_GENERATEUR_DOCUMENTS,
            Constantes.CONFIG_QUEUE_NOTIFICATIONS: Constantes.DEFAUT_QUEUE_NOTIFICATIONS,
            Constantes.CONFIG_MQ_EXCHANGE_MIDDLEWARE: Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE,
            Constantes.CONFIG_MQ_EXCHANGE_NOEUDS: Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            Constantes.CONFIG_MQ_EXCHANGE_PRIVE: Constantes.DEFAUT_MQ_EXCHANGE_PRIVE,
            Constantes.CONFIG_MQ_EXCHANGE_PUBLIC: Constantes.DEFAUT_MQ_EXCHANGE_PUBLIC,
            Constantes.CONFIG_MQ_USER: Constantes.DEFAUT_MQ_USER,
            Constantes.CONFIG_MQ_PASSWORD: None,
            Constantes.CONFIG_MQ_SSL: 'on',  # Options on, off.
            Constantes.CONFIG_MQ_AUTH_CERT: 'off',  # Options on, off.
            Constantes.CONFIG_MQ_KEYFILE: Constantes.DEFAUT_KEYFILE,
            Constantes.CONFIG_MQ_CERTFILE: Constantes.DEFAUT_CERTFILE,
            Constantes.CONFIG_MQ_CA_CERTS: Constantes.DEFAUT_CA_CERTS,
        }

        self._pki_config = {
            Constantes.CONFIG_PKI_WORKDIR: Constantes.DEFAUT_PKI_WORKDIR,
            Constantes.CONFIG_MAITREDESCLES_DIR: Constantes.DEFAUT_MAITREDESCLES_DIR,
            Constantes.CONFIG_PKI_SECRET_DIR: Constantes.DEFAUT_PKI_SECRET_DIR,
            Constantes.CONFIG_PKI_CERT_MILLEGRILLE: Constantes.DEFAUT_PKI_CERT_MILLEGRILLE,
            Constantes.CONFIG_PKI_KEY_MILLEGRILLE: Constantes.DEFAUT_PKI_KEY_MILLEGRILLE,
            Constantes.CONFIG_PKI_PASSWORD_MILLEGRILLE: Constantes.DEFAUT_PKI_PASSWORD_MILLEGRILLE,
            Constantes.CONFIG_PKI_CERT_AUTORITE: Constantes.DEFAUT_PKI_CERT_AUTORITE,
            Constantes.CONFIG_PKI_KEY_AUTORITE: Constantes.DEFAUT_PKI_KEY_AUTORITE,
            Constantes.CONFIG_PKI_PASSWORD_AUTORITE: Constantes.DEFAUT_PKI_PASSWORD_AUTORITE,
            Constantes.CONFIG_PKI_CERT_MAITREDESCLES: Constantes.DEFAUT_PKI_CERT_MAITREDESCLES,
            Constantes.CONFIG_PKI_KEY_MAITREDESCLES: Constantes.DEFAUT_PKI_KEY_MAITREDESCLES,
            Constantes.CONFIG_PKI_PASSWORD_MAITREDESCLES: Constantes.DEFAUT_PKI_PASSWORD_MAITREDESCLES,
            Constantes.CONFIG_CA_PASSWORDS: Constantes.DEFAULT_CA_PASSWORDS,
        }

        # Configuration de connection a MongoDB
        self._mongo_config = {
            Constantes.CONFIG_MONGO_HOST: Constantes.DEFAUT_HOSTNAME,
            Constantes.CONFIG_MONGO_PORT: '27017',
            # Constantes.CONFIG_MONGO_USER: 'root',
            # Constantes.CONFIG_MONGO_PASSWORD: 'example',
            Constantes.CONFIG_MONGO_SSL: 'x509',   # Options on, off, x509, nocert
            Constantes.CONFIG_MONGO_SSL_CAFILE: Constantes.DEFAUT_CA_CERTS,
            Constantes.CONFIG_MONGO_SSL_KEYFILE: Constantes.DEFAUT_KEYCERTFILE
        }

        self._domaines_config = {
            Constantes.CONFIG_DOMAINES_CONFIGURATION: None
        }

        # Configuration specifique a la MilleGrille
        self._millegrille_config = {
            Constantes.CONFIG_IDMG: Constantes.DEFAUT_IDMG  # Fingerprint SHA-1 en base58 du certificat racine
        }

        self._email_config = {
            Constantes.CONFIG_EMAIL_HOST: None,
            Constantes.CONFIG_EMAIL_PORT: None,
            Constantes.CONFIG_EMAIL_USER: None,
            Constantes.CONFIG_EMAIL_PASSWORD: None,
            Constantes.CONFIG_EMAIL_TO: None,
            Constantes.CONFIG_EMAIL_FROM: None
        }

        self._serveurs = {
            Constantes.CONFIG_SERVEUR_CONSIGNATIONFICHIERS_HOST: Constantes.DEFAUT_CONSIGNATIONFICHIERS_HOST,
            Constantes.CONFIG_SERVEUR_CONSIGNATIONFICHIERS_PORT: Constantes.DEFAUT_CONSIGNATIONFICHIERS_PORT,
        }

        self._backup = {
            Constantes.CONFIG_BACKUP_WORKDIR: Constantes.DEFAUT_BACKUP_WORKDIR,
        }

    def loadEnvironment(self, additionals: list = None):
        fichier_json_path = os.environ.get(Constantes.CONFIG_FICHIER_JSON.upper())
        dict_fichier_json = dict()
        if fichier_json_path is not None:
            logging.info("Chargement fichier JSON")
            # Charger le fichier et combiner au dictionnaire
            with open(fichier_json_path) as fjson:
                dict_fichier_json = json.load(fjson)
                # logging.debug("Config JSON: %s" % str(dict_fichier_json))

        if additionals is not None:
            [dict_fichier_json.update(a) for a in additionals]

        # Faire la liste des dictionnaires de configuration a charger
        configurations = [
            self._mq_config,
            self._mongo_config,
            self._millegrille_config,
            self._domaines_config,
            self._email_config,
            self._pki_config,
            self._serveurs,
            self._backup,
        ]

        for config_dict in configurations:

            # Configuration de connection a RabbitMQ
            for property in config_dict.keys():
                env_value = os.environ.get('%s%s' % (Constantes.PREFIXE_ENV_MG, property.upper()))
                json_value = dict_fichier_json.get('%s%s' % (Constantes.PREFIXE_ENV_MG, property.upper()))
                if env_value is not None :
                    config_dict[property] = env_value
                elif json_value is not None:
                    config_dict[property] = json_value

        # Si le IDMG n'est pas fourni, tenter de le charger a partir du certificat MQ
        if self.idmg == Constantes.DEFAUT_IDMG:
            try:
                with open(self.pki_certfile, 'rb') as fichier:
                    pem = fichier.read()
                    certificat = default_backend().load_pem_x509_certificate(pem)
                    organization = certificat.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                    if len(organization) > 0:
                        self._millegrille_config[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG] = organization[0].value
            except FileNotFoundError:
                self.__logger.exception("IDMG inconne, on utilise sansnom")

    def load_property(self, map, property, env_name):
        env_value = os.environ[env_name]
        if env_value is not None:
            map[property] = env_value

    def format_mongo_config(self):
        """ Formatte la configuration pour connexion a Mongo """

        config_mongo = dict()

        parametres_mongo = ['host', 'username', 'password']
        parametres_mongo_int = ['port']

        # Configuration specifique pour ssl
        mongo_ssl_param = self._mongo_config.get(Constantes.CONFIG_MONGO_SSL)
        config_mongo['ssl'] = mongo_ssl_param in ['on', 'nocert', 'x509']  # Mettre ssl=True ou ssl=False
        if mongo_ssl_param == 'on':
            config_mongo['ssl_cert_reqs'] = ssl.CERT_REQUIRED
            parametres_mongo.extend(['ssl_certfile', 'ssl_ca_certs'])
        elif mongo_ssl_param == 'x509':
            config_mongo['authMechanism'] = 'MONGODB-X509'
            parametres_mongo.extend(['ssl_certfile', 'ssl_ca_certs'])
        elif mongo_ssl_param == 'nocert':
            config_mongo['ssl_cert_reqs'] = ssl.CERT_NONE

        if mongo_ssl_param != 'x509':
            config_mongo['authSource'] = self.idmg

        # Copier toutes les valeurs necessaires, enlever le prefixe mongo_ de chaque cle.
        for cle in self._mongo_config:
            cle_mongo = cle.replace('mongo_', '')
            if cle_mongo in parametres_mongo_int:
                valeur = int(self._mongo_config[cle])
                config_mongo[cle_mongo] = valeur
            elif cle_mongo in parametres_mongo:
                valeur = self._mongo_config[cle]
                config_mongo[cle_mongo] = valeur

        return config_mongo

    @property
    def mq_host(self):
        return self._mq_config[Constantes.CONFIG_MQ_HOST]

    @property
    def mq_port(self):
        return int(self._mq_config[Constantes.CONFIG_MQ_PORT])

    @property
    def mq_virtual_host(self):
        return self._mq_config[Constantes.CONFIG_MQ_VIRTUAL_HOST]

    @property
    def mq_user(self):
        return self._mq_config[Constantes.CONFIG_MQ_USER]

    @property
    def mq_password(self):
        return self._mq_config[Constantes.CONFIG_MQ_PASSWORD]

    @property
    def mq_heartbeat(self):
        return int(self._mq_config[Constantes.CONFIG_MQ_HEARTBEAT])

    @property
    def mq_ssl(self):
        return self._mq_config[Constantes.CONFIG_MQ_SSL]

    @property
    def mq_auth_cert(self):
        return self._mq_config[Constantes.CONFIG_MQ_AUTH_CERT]

    @property
    def mq_keyfile(self):
        return self._mq_config[Constantes.CONFIG_MQ_KEYFILE]

    @property
    def mq_certfile(self):
        return self._mq_config[Constantes.CONFIG_MQ_CERTFILE]

    @property
    def mq_cafile(self):
        return self._mq_config[Constantes.CONFIG_MQ_CA_CERTS]

    @property
    def pki_keyfile(self):
        return self._mq_config[Constantes.CONFIG_MQ_KEYFILE]

    @property
    def pki_certfile(self):
        return self._mq_config[Constantes.CONFIG_MQ_CERTFILE]

    @property
    def pki_cafile(self):
        return self._mq_config[Constantes.CONFIG_MQ_CA_CERTS]

    @property
    def pki_workdir(self):
        return self._pki_config[Constantes.CONFIG_PKI_WORKDIR]

    @property
    def pki_secretdir(self):
        return self._pki_config[Constantes.CONFIG_PKI_SECRET_DIR]

    @property
    def pki_keyautorite(self):
        return self._pki_config[Constantes.CONFIG_PKI_KEY_AUTORITE]

    @property
    def pki_capasswords(self):
        return self._pki_config[Constantes.CONFIG_CA_PASSWORDS]

    @property
    def pki_config(self):
        return self._pki_config

    @property
    def idmg(self):
        return self._millegrille_config[Constantes.CONFIG_IDMG]

    @property
    def mongo_host(self):
        return self._mongo_config[Constantes.CONFIG_MONGO_HOST]

    @property
    def mongo_port(self):
        return int(self._mongo_config[Constantes.CONFIG_MONGO_PORT])

    @property
    def mongo_user(self):
        return self._mongo_config[Constantes.CONFIG_MONGO_USER]

    @property
    def mongo_password(self):
        return self._mongo_config[Constantes.CONFIG_MONGO_PASSWORD]

    @property
    def mongo_ssl(self):
        return self._mongo_config[Constantes.CONFIG_MONGO_SSL]

    @property
    def mongo_keycert(self):
        return self._mongo_config[Constantes.CONFIG_MONGO_SSL_KEYFILE]

    @property
    def queue_nouvelles_transactions(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_NOUVELLES_TRANSACTIONS]

    @property
    def queue_evenements_transactions(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_EVENEMENTS_TRANSACTIONS]

    @property
    def queue_erreurs_transactions(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_ERREURS_TRANSACTIONS]

    @property
    def queue_mgp_processus(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_MGP_PROCESSUS]

    @property
    def queue_erreurs_processus(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_ERREURS_PROCESSUS]

    @property
    def exchange_middleware(self):
        return self._mq_config[Constantes.CONFIG_MQ_EXCHANGE_MIDDLEWARE]

    @property
    def exchange_secure(self):
        return self._mq_config[Constantes.CONFIG_MQ_EXCHANGE_MIDDLEWARE]

    @property
    def exchange_protege(self):
        return self._mq_config[Constantes.CONFIG_MQ_EXCHANGE_NOEUDS]

    @property
    def exchange_prive(self):
        return self._mq_config[Constantes.CONFIG_MQ_EXCHANGE_PRIVE]

    @property
    def exchange_noeuds(self):
        return self._mq_config[Constantes.CONFIG_MQ_EXCHANGE_NOEUDS]

    @property
    def exchange_public(self):
        return self._mq_config[Constantes.CONFIG_MQ_EXCHANGE_PUBLIC]

    @property
    def queue_generateur_documents(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_GENERATEUR_DOCUMENTS]

    @property
    def queue_notifications(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_NOTIFICATIONS]

    @property
    def domaines_json(self):
        return self._domaines_config[Constantes.CONFIG_DOMAINES_CONFIGURATION]

    @property
    def email_host(self):
        return self._email_config[Constantes.CONFIG_EMAIL_HOST]

    @property
    def email_port(self):
        return self._email_config[Constantes.CONFIG_EMAIL_PORT]

    @property
    def email_user(self):
        return self._email_config[Constantes.CONFIG_EMAIL_USER]

    @property
    def email_password(self):
        return self._email_config[Constantes.CONFIG_EMAIL_PASSWORD]

    @property
    def email_to(self):
        return self._email_config[Constantes.CONFIG_EMAIL_TO]

    @property
    def email_from(self):
        return self._email_config[Constantes.CONFIG_EMAIL_FROM]

    @property
    def serveur_consignationfichiers_host(self):
        return self._serveurs[Constantes.CONFIG_SERVEUR_CONSIGNATIONFICHIERS_HOST]

    @property
    def serveur_consignationfichiers_port(self):
        return self._serveurs[Constantes.CONFIG_SERVEUR_CONSIGNATIONFICHIERS_PORT]

    @property
    def backup_workdir(self):
        return self._backup[Constantes.CONFIG_BACKUP_WORKDIR]


class ContexteRessourcesMilleGrilles:
    """ Classe helper qui permet d'initialiser et de passer les ressources (configuration, DAOs) """

    def __init__(self, configuration: TransactionConfiguration = None, message_dao=None, additionals: list = None):
        """
        Init classe. Fournir les ressources deja initialisee ou utiliser methode initialiser().

        :param configuration: Optionnel, configuration MilleGrilles deja initialisee.
        :param message_dao: Optionnel, message_dao deja initialise.
        :param additionals: Fichiers de config additionels a combiner
        """

        self._configuration = configuration
        self._message_dao = message_dao
        self._additionnals = additionals

        self._email_dao = None
        self._signateur_transactions = None
        self._generateur_transactions = None

    def initialiser(self, init_message=True, connecter=True):
        """
        Initialise/reinitialise le contexte et connecte les DAOs.

        :param init_message: Si True, initialise et connecte PikaDAO
        :param connecter: Si true, la connexion aux DAOs est ouverte immediatement
        """

        self._configuration = TransactionConfiguration()
        self._configuration.loadEnvironment(additionals=self._additionnals)
        self._message_dao = None

        if init_message:
            self._message_dao = PikaDAO(self._configuration)
            self._signateur_transactions = SignateurTransaction(self)
            self._signateur_transactions.initialiser()
            if connecter:
                self._message_dao.connecter()

    @property
    def configuration(self):
        return self._configuration

    @property
    def message_dao(self) -> PikaDAO:
        """
        Retourne un message_dao.

        :return: Message dao.
        :raises: ValueError is le message dao n'a pas ete defini.
        """

        # if self._message_dao is None:
        #     raise ValueError("MessageDAO n'est pas initialise")
        return self._message_dao

    @message_dao.setter
    def message_dao(self, message_dao):
        self._message_dao = message_dao

    @property
    def generateur_transactions(self) -> GenerateurTransaction:
        if self._generateur_transactions is None:
            self._generateur_transactions = GenerateurTransaction(self)
        return self._generateur_transactions

    @property
    def signateur_transactions(self) -> SignateurTransaction:
        return self._signateur_transactions

    @property
    def idmg(self) -> str:
        return self._configuration.idmg

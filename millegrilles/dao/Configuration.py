# Configuration pour traiter les transactions

import os
import json
import logging
import ssl

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from typing import Optional
from threading import Thread, Event

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.SecuritePKI import SignateurTransaction, VerificateurTransaction, VerificateurCertificats
from millegrilles.util.X509Certificate import EnveloppeCleCert
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.util.ValidateursPki import ValidateurCertificat


class TransactionConfiguration:

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        # Configuration de connection a RabbitMQ

        self._mq_config = {
            Constantes.CONFIG_MQ_HOST: Constantes.DEFAUT_HOSTNAME,
            Constantes.CONFIG_MQ_PORT: '5673',
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
            Constantes.CONFIG_MQ_EXCHANGE_DEFAUT: Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
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
            Constantes.CONFIG_PKI_CERTFILE: '',
            Constantes.CONFIG_PKI_KEYFILE: '',
            Constantes.CONFIG_PKI_CERT_INTERMEDIAIRE: '',
            Constantes.CONFIG_PKI_KEY_INTERMEDIAIRE: '',
            Constantes.CONFIG_PKI_PASSWORD_INTERMEDIAIRE: '',
            Constantes.CONFIG_PKI_CERT_MILLEGRILLE: '',
            Constantes.CONFIG_PKI_KEY_MILLEGRILLE: '',
            Constantes.CONFIG_PKI_PASSWORD_MILLEGRILLE: '',
            Constantes.CONFIG_PKI_CERT_MAITREDESCLES: '',
            Constantes.CONFIG_PKI_KEY_MAITREDESCLES: '',
            Constantes.CONFIG_PKI_PASSWORD_MAITREDESCLES: '',
            Constantes.CONFIG_CA_PASSWORDS: '',
            Constantes.CONFIG_PKI_CLECERT_INTERMEDIAIRE: '',
        }

        # Configuration de connection a MongoDB
        self._mongo_config = {
            Constantes.CONFIG_MONGO_HOST: Constantes.DEFAUT_HOSTNAME_MONGO,
            Constantes.CONFIG_MONGO_PORT: '27017',
            Constantes.CONFIG_MONGO_USER: 'root',
            Constantes.CONFIG_MONGO_PASSWORD: 'example',
            Constantes.CONFIG_MONGO_SSL: 'x509',   # Options on, off, x509, nocert
            Constantes.CONFIG_MONGO_SSL_CAFILE: Constantes.DEFAUT_CA_CERTS,
            Constantes.CONFIG_MONGO_SSL_KEYFILE: Constantes.DEFAUT_KEYCERTFILE,
            Constantes.CONFIG_MONGO_AUTHSOURCE: None,
        }

        self._domaines_config = {
            Constantes.CONFIG_DOMAINES_CONFIGURATION: None,
            Constantes.CONFIG_DOMAINES_DYNAMIQUES: None,
        }

        # Configuration specifique a la MilleGrille
        self._millegrille_config = {
            Constantes.CONFIG_IDMG: Constantes.DEFAUT_IDMG,  # Fingerprint SHA-1 en base58 du certificat racine
            Constantes.CONFIG_NOEUD_ID: None                 # Fingerprint SHA-1 en base58 du certificat racine
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

        # Cle et certificat du module
        self.__cle: Optional[EnveloppeCleCert] = None

        self._backup_workdir: Optional[str] = None

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
                value = self.find_value(dict_fichier_json, property)
                if value is not None:
                    config_dict[property] = value

        # Si le IDMG n'est pas fourni, tenter de le charger a partir du certificat MQ
        if self.idmg == Constantes.DEFAUT_IDMG:
            try:
                with open(self.pki_certfile, 'rb') as fichier:
                    pem = fichier.read()
                    certificat = default_backend().load_pem_x509_certificate(pem)
                    organization = certificat.issuer.get_attributes_for_oid(x509.name.NameOID.ORGANIZATION_NAME)
                    if len(organization) > 0:
                        self._millegrille_config[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG] = organization[0].value
            except FileNotFoundError:
                self.__logger.exception("IDMG inconnue, on utilise sansnom")
                pem = None
        else:
            with open(self.pki_certfile, 'rb') as fichier:
                pem = fichier.read()

        if pem is not None:
            # Tenter de charger la cle associee au certificat
            try:
                with open(self.pki_keyfile, 'rb') as fichier:
                    cle = fichier.read()
            except FileNotFoundError:
                # Cle non present, on charge le certificat
                clecert = EnveloppeCleCert()
                clecert.cert_from_pem_bytes(pem)
                self.__cle = clecert
            else:
                # Cle et certificat presents, on charge clecert avec les deux
                clecert = EnveloppeCleCert()
                clecert.from_pem_bytes(private_key_bytes=cle, cert_bytes=pem)

                if not clecert.cle_correspondent():
                    self.__logger.warning(
                        "TransactionConfiguration.loadEnvironnemnt: Cle et certificat du module ne correspondent pas, "
                        "on ignore la cle"
                    )
                    clecert = EnveloppeCleCert()
                    clecert.cert_from_pem_bytes(pem)

                self.__cle = clecert

        self.__logger.info("Configuration MQ: host: %s, port: %s" % (self.mq_host, self.mq_port))
        self.__logger.info("Configuration Mongo: host: %s, port: %s" % (self.mongo_host, self.mongo_port))

    def find_value(self, dict_fichier_json, property):
        value = os.environ.get('%s%s' % (Constantes.PREFIXE_ENV_MG, property.upper()))
        if not value:
            value = dict_fichier_json.get('%s%s' % (Constantes.PREFIXE_ENV_MG, property.upper()))
        return value

    def load_property(self, map, property, env_name):
        env_value = os.environ[env_name]
        if env_value is not None:
            map[property] = env_value

    def format_mongo_config(self):
        """ Formatte la configuration pour connexion a Mongo """

        config_mongo = dict()

        parametres_mongo = ['host']
        parametres_mongo_int = ['port']

        # Configuration specifique pour ssl
        mongo_ssl_param = self._mongo_config.get(Constantes.CONFIG_MONGO_SSL)
        config_mongo['ssl'] = mongo_ssl_param in ['on', 'nocert', 'x509']  # Mettre ssl=True ou ssl=False
        config_mongo['authSource'] = self._mongo_config.get(Constantes.CONFIG_MONGO_AUTHSOURCE) or self.idmg
        if mongo_ssl_param == 'on':
            config_mongo['ssl_cert_reqs'] = ssl.CERT_REQUIRED
            # parametres_mongo.extend(['ssl_certfile', 'ssl_ca_certs', 'username', 'password'])
            parametres_mongo.extend(['username', 'password'])
        elif mongo_ssl_param == 'x509':
            config_mongo['ssl_cert_reqs'] = ssl.CERT_REQUIRED
            config_mongo['authMechanism'] = 'MONGODB-X509'
            # parametres_mongo.extend(['ssl_certfile', 'ssl_ca_certs'])
            del config_mongo['authSource']
        elif mongo_ssl_param == 'nocert':
            config_mongo['ssl_cert_reqs'] = ssl.CERT_NONE
            parametres_mongo.extend(['username', 'password'])

        if mongo_ssl_param in ['x509', 'on']:
            # Copier key/cert MQ. Va etre override au besoin
            config_mongo['ssl_certfile'] = self.mq_certfile
            config_mongo['ssl_keyfile'] = self.mq_keyfile
            config_mongo['ssl_ca_certs'] = self.mq_cafile

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
        fichier = self._pki_config[Constantes.CONFIG_PKI_KEYFILE]
        if fichier == '':
            fichier = self.mq_keyfile
        return fichier

    @property
    def pki_certfile(self):
        fichier = self._pki_config[Constantes.CONFIG_PKI_CERTFILE]
        if fichier == '':
            fichier = self.mq_certfile
        return fichier

    @property
    def pki_cafile(self):
        fichier = self._pki_config[Constantes.CONFIG_PKI_CERT_MILLEGRILLE]
        if fichier == '':
            fichier = self.mq_cafile
        return fichier

    @property
    def pki_workdir(self):
        return self._pki_config[Constantes.CONFIG_PKI_WORKDIR]

    @property
    def pki_secretdir(self):
        return self._pki_config[Constantes.CONFIG_PKI_SECRET_DIR]

    @property
    def pki_keymillegrille(self):
        return self._pki_config[Constantes.CONFIG_PKI_KEY_MILLEGRILLE]

    @property
    def pki_capasswords(self):
        return self._pki_config[Constantes.CONFIG_CA_PASSWORDS]

    @property
    def pki_password_millegrille(self):
        return self._pki_config[Constantes.CONFIG_PKI_PASSWORD_MILLEGRILLE]

    @property
    def pki_config(self):
        return self._pki_config

    @property
    def idmg(self):
        return self._millegrille_config[Constantes.CONFIG_IDMG]

    @property
    def noeud_id(self):
        return self._millegrille_config[Constantes.CONFIG_NOEUD_ID]

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
    def mongo_authsource(self):
        return self._mongo_config[Constantes.CONFIG_MONGO_AUTHSOURCE]

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
        return Constantes.SECURITE_SECURE

    @property
    def exchange_secure(self):
        return Constantes.SECURITE_SECURE

    @property
    def exchange_protege(self):
        return Constantes.SECURITE_PROTEGE

    @property
    def exchange_prive(self):
        return Constantes.SECURITE_PRIVE

    @property
    def exchange_noeuds(self):
        return Constantes.SECURITE_PROTEGE

    @property
    def exchange_public(self):
        return Constantes.SECURITE_PUBLIC

    @property
    def exchange_defaut(self):
        return self._mq_config[Constantes.CONFIG_MQ_EXCHANGE_DEFAUT]

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
    def domaines_dynamiques(self):
        return self._domaines_config[Constantes.CONFIG_DOMAINES_DYNAMIQUES]

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
        return self._backup_workdir or self._backup[Constantes.CONFIG_BACKUP_WORKDIR]

    @backup_workdir.setter
    def backup_workdir(self, backup_workdir: str):
        self._backup_workdir = backup_workdir

    @property
    def cle(self) -> EnveloppeCleCert:
        return self.__cle

    @cle.setter
    def cle(self, cle: EnveloppeCleCert):
        self.__cle = cle


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
        # self._verificateur_certificats = None  # Deprecated
        # self._verificateur_transactions = None  # Deprecated
        self._generateur_transactions = None

        # Validateur de messages (inclus validateur de certificats)
        self._validateur_message: Optional[ValidateurMessage] = None

        # self.validation_workdir_tmp = None

        # Thread pour l'entretien du contexte, demarree automatiqement sur connexion
        self.__thread_entretien = Thread(name="ctxmaint", target=self.__entretien, daemon=True)
        self.__stop_event = Event()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initialiser(self, init_message=True, connecter=True):
        """
        Initialise/reinitialise le contexte et connecte les DAOs.

        :param init_message: Si True, initialise et connecte PikaDAO
        :param connecter: Si true, la connexion aux DAOs est ouverte immediatement
        """

        if not self._configuration:
            self._configuration = TransactionConfiguration()
        self._configuration.loadEnvironment(additionals=self._additionnals)
        self._message_dao = None

        # self.validation_workdir_tmp = tempfile.mkdtemp(prefix='millegrilles_pki_', dir=self._configuration.pki_workdir)

        if init_message:
            self._message_dao = PikaDAO(self._configuration)
            self._signateur_transactions = SignateurTransaction(self)
            self._signateur_transactions.initialiser()

            # Preparer les certificats, validateurs
            # self._verificateur_transactions = VerificateurTransaction(self)
            # self._verificateur_certificats = VerificateurCertificats(self)
            # self._verificateur_transactions.initialiser()
            # self._verificateur_certificats.initialiser()

            self._validateur_message = ValidateurMessage(self)

            if connecter:
                self.connecter()

    def connecter(self):
        self._message_dao.connecter()
        self._validateur_message.connecter()

        self.__stop_event.clear()
        self.__thread_entretien.start()

    def fermer(self):
        # try:
        #     shutil.rmtree(self.validation_workdir_tmp)
        # except Exception as e:
        #     self.__logger.warning("Erreur suppression workdir pki tmp : %s", str(e))
        self.__stop_event.set()

        try:
            self._message_dao.deconnecter()
        except:
            pass

        try:
            self._validateur_message.fermer()
        except:
            pass

    def __entretien(self):
        """
        Effectue l'entretien des modules du contexte.
        """

        while not self.__stop_event.is_set():
            try:
                self.validateur_message.entretien()
            except Exception:
                self.__logger.exception("Erreur d'entretien du validateur de messages")

            # Entretien toutes les 30 secondes
            self.__stop_event.wait(30)

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
    def verificateur_transaction(self) -> VerificateurTransaction:
        raise NotImplementedError("Deprecated")
        # return self._verificateur_transactions

    @property
    def verificateur_certificats(self) -> VerificateurCertificats:
        raise NotImplementedError("Deprecated")
        # return self._verificateur_certificats

    @property
    def idmg(self) -> str:
        return self._configuration.idmg

    @property
    def validateur_message(self) -> ValidateurMessage:
        return self._validateur_message

    @property
    def validateur_pki(self) -> ValidateurCertificat:
        return self._validateur_message.validateur_pki

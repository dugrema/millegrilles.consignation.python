# Configuration pour traiter les transactions

import os
import json
import logging
from millegrilles import Constantes


class TransactionConfiguration:

    def __init__(self):
        # Configuration de connection a RabbitMQ
        self._mq_config = {
            Constantes.CONFIG_MQ_HOST: 'localhost',
            Constantes.CONFIG_MQ_PORT: '5671',
            Constantes.CONFIG_QUEUE_NOUVELLES_TRANSACTIONS: Constantes.DEFAUT_QUEUE_NOUVELLES_TRANSACTIONS,
            Constantes.CONFIG_QUEUE_ERREURS_TRANSACTIONS: Constantes.DEFAUT_QUEUE_ERREURS_TRANSACTIONS,
            Constantes.CONFIG_QUEUE_MGP_PROCESSUS: Constantes.DEFAUT_QUEUE_MGP_PROCESSUS,
            Constantes.CONFIG_QUEUE_ERREURS_PROCESSUS: Constantes.DEFAUT_QUEUE_ERREURS_PROCESSUS,
            Constantes.CONFIG_QUEUE_GENERATEUR_DOCUMENTS: Constantes.DEFAUT_QUEUE_GENERATEUR_DOCUMENTS,
            Constantes.CONFIG_QUEUE_NOTIFICATIONS: Constantes.DEFAUT_QUEUE_NOTIFICATIONS,
            Constantes.CONFIG_MQ_EXCHANGE_EVENEMENTS: Constantes.DEFAUT_MQ_EXCHANGE_EVENEMENTS,
            Constantes.CONFIG_MQ_USER: Constantes.DEFAUT_MQ_USER,
            Constantes.CONFIG_MQ_PASSWORD: None,
            Constantes.CONFIG_MQ_SSL: 'on'  # Options on, off.
        }

        # Configuration de connection a MongoDB
        self._mongo_config = {
            Constantes.CONFIG_MONGO_HOST: 'localhost',
            Constantes.CONFIG_MONGO_PORT: '27017',
            Constantes.CONFIG_MONGO_USER: 'root',
            Constantes.CONFIG_MONGO_PASSWORD: 'example',
            Constantes.CONFIG_MONGO_SSL: 'on'   # Options on, off, nocert
        }

        self._domaines_config = {
            Constantes.CONFIG_DOMAINES_CONFIGURATION: None
        }

        # Configuration specifique a la MilleGrille
        self._millegrille_config = {
            Constantes.CONFIG_NOM_MILLEGRILLE: Constantes.DEFAUT_NOM_MILLEGRILLE # Nom de la MilleGrille
        }

    def loadEnvironment(self):
        fichier_json_path = os.environ.get(Constantes.CONFIG_FICHIER_JSON.upper())
        dict_fichier_json = dict()
        if fichier_json_path is not None:
            logging.info("Chargement fichier JSON")
            # Charger le fichier et combiner au dictionnaire
            with open(fichier_json_path) as fjson:
                dict_fichier_json = json.load(fjson)
                # logging.debug("Config JSON: %s" % str(dict_fichier_json))

        # Faire la liste des dictionnaires de configuration a charger
        configurations = [self._mq_config, self._mongo_config, self._millegrille_config, self._domaines_config]

        for config_dict in configurations:

            # Configuration de connection a RabbitMQ
            for property in config_dict.keys():
                env_value = os.environ.get('%s%s' % (Constantes.PREFIXE_ENV_MG, property.upper()))
                json_value = dict_fichier_json.get('%s%s' % (Constantes.PREFIXE_ENV_MG, property.upper()))
                if env_value is not None :
                    config_dict[property] = env_value
                elif json_value is not None:
                    config_dict[property] = json_value

    def load_property(self, map, property, env_name):
        env_value = os.environ[env_name]
        if env_value is not None:
            map[property] = env_value

    @property
    def mq_host(self):
        return self._mq_config[Constantes.CONFIG_MQ_HOST]

    @property
    def mq_port(self):
        return int(self._mq_config[Constantes.CONFIG_MQ_PORT])

    @property
    def mq_user(self):
        return self._mq_config[Constantes.CONFIG_MQ_USER]

    @property
    def mq_password(self):
        return self._mq_config[Constantes.CONFIG_MQ_PASSWORD]

    @property
    def mq_ssl(self):
        return self._mq_config[Constantes.CONFIG_MQ_SSL]

    @property
    def nom_millegrille(self):
        return self._millegrille_config[Constantes.CONFIG_NOM_MILLEGRILLE]

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
    def queue_nouvelles_transactions(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_NOUVELLES_TRANSACTIONS]

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
    def exchange_evenements(self):
        return self._mq_config[Constantes.CONFIG_MQ_EXCHANGE_EVENEMENTS]

    @property
    def queue_generateur_documents(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_GENERATEUR_DOCUMENTS]

    @property
    def queue_notifications(self):
        return self._mq_config[Constantes.CONFIG_QUEUE_NOTIFICATIONS]

    @property
    def domaines_json(self):
        return self._domaines_config[Constantes.CONFIG_DOMAINES_CONFIGURATION]
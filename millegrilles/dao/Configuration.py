''' Configuration pour traiter les transactions
'''

import os

class TransactionConfiguration:

    def __init__(self):
        # Configuration de connection a RabbitMQ
        self._mq_config = {
            'mq_host': "localhost",
            'mq_port': '5672',
            'mq_queue_nouvelles_transactions': 'nouvelles_transactions',
            'mq_queue_entree_processus': 'entree_processus',
            'mq_exchange_evenements': 'millegrilles.evenements'
        }

        # Configuration de connection a MongoDB
        self._mongo_config = {
            'mongo_host': 'localhost',
            'mongo_port': '27017',
            'mongo_user': 'root',
            'mongo_password': 'example'
        }

        # Configuration specifique a la MilleGrille
        self._millegrille_config = {
            'nom_millegrille': 'sansnom' # Nom de la MilleGrille
        }

    def loadEnvironment(self):
        # Faire la liste des dictionnaires de configuration a charger
        configurations = [self._mq_config, self._mongo_config, self._millegrille_config]

        for config_dict in configurations:

            # Configuration de connection a RabbitMQ
            for property in config_dict.keys():
                env_value = os.environ.get('MG_%s' %property.upper())
                if(env_value != None):
                    config_dict[property] = env_value

    def loadProperty(self, map, property, env_name):
        env_value = os.environ[env_name]
        if(env_value != None):
            map[property] = env_value

    @property
    def mq_host(self):
        return self._mq_config['mq_host']

    @property
    def mq_port(self):
        return int(self._mq_config['mq_port'])

    @property
    def nom_millegrille(self):
        return self._millegrille_config['nom_millegrille']

    @property
    def mongo_host(self):
        return self._mongo_config['mongo_host']

    @property
    def mongo_port(self):
        return int(self._mongo_config['mongo_port'])

    @property
    def mongo_user(self):
        return self._mongo_config['mongo_user']

    @property
    def mongo_password(self):
        return self._mongo_config['mongo_password']

    @property
    def queue_nouvelles_transactions(self):
        return self._mq_config['mq_queue_nouvelles_transactions']

    @property
    def queue_entree_processus(self):
        return self._mq_config['mq_queue_entree_processus']

    @property
    def exchange_evenements(self):
        return self._mq_config['mq_exchange_evenements']

''' Configuration pour traiter les transactions
'''

import os

class TransactionConfiguration:

    def __init__(self):
        # Configuration de connection a RabbitMQ
        self._mq_host = "dev2"
        self._mq_port = 5672
        self._mq_queue_nouvelles_transactions = "nouvelles_transactions"

        # Configuration de connection a MongoDB
        self._mongo_host = "dev2"
        self._mongo_port = 27017
        self._mongo_user = "root"
        self._mongo_password = "example"

        # Configuration specifique a la MilleGrille
        self._nom_millegrille = "sansnom" # Nom de la MilleGrille

    def loadEnvironment(self):
        # Configuration de connection a RabbitMQ
        self._mq_host = os.environ['MG_MSG_HOST']
        self._mq_port = os.environ['MG_MSG_PORT']

        # Configuration de connection a MongoDB
        self._mongo_host = os.environ['MG_MONGO_HOST']
        self._mongo_port = os.environ['MG_MONGO_PORT']
        self._mongo_user = os.environ['MG_MONGO_USER']
        self._mongo_password = os.environ['MG_MONGO_PASSWORD']

        # Configuration specifique a la MilleGrille
        self._nom_millegrille = os.environ['MG_NOM']

    @property
    def mq_host(self):
        return self._mq_host

    @property
    def mq_port(self):
        return self._mq_port

    @property
    def nom_millegrille(self):
        return self._nom_millegrille

    @property
    def queue_nouvelles_transactions(self):
        return "mg.%s.%s" % (self._nom_millegrille, self._mq_queue_nouvelles_transactions)

    @property
    def mongo_host(self):
        return self._mongo_host

    @property
    def mongo_port(self):
        return self._mongo_port

    @property
    def mongo_user(self):
        return self._mongo_user

    @property
    def mongo_password(self):
        return self._mongo_password


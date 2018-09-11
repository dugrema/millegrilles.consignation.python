''' Configuration pour traiter les transactions
'''

class TransactionConfiguration:

    def __init__(self):
        # Configuration de connection a l'hote
        self._mq_host = "dev2"
        self._mq_port = 5672
        self._nom_millegrille = "sansnom" # Nom de la MilleGrille

        # Configuration des queues
        self._mq_queue_nouvelles_transactions = "nouvelles_transactions"

    def loadEnvironment(self):
        self._mq_host = os.environ['MG_MSG_HOST']
        self._mq_port = os.environ['MG_MSG_PORT']
        self._nom_millegrille = os.environ['MG_NOM']

        #self.mq_queue = os.environ['MQ_QUEUE_NOUVTRAN']

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


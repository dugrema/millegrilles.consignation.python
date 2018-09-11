''' Configuration pour traiter les transactions
'''

class TransactionConfiguration:

    def __init__(self):
        # Configuration de connection a l'hote
        self.mq_host = "dev2" #os.environ['MQ_HOST']
        self.mq_port = 5672

        # Configuration des queues
        self.mq_queue_nouvelles_transactions = "mg.nouvelles_transactions"

    def loadEnvironment(self):
        self.mq_host = os.environ['MQ_HOST']
        elf.mq_host = os.environ['MQ_PORT']

        #self.mq_queue = os.environ['MQ_QUEUE_NOUVTRAN']

    @property
    def mqHost(self):
        return self.mq_host

    @property
    def mqPort(self):
        return self.mq_port

    @property
    def mqQueueNouvellesTransactions(self):
        return self.mq_queue_nouvelles_transactions


''' Configuration pour traiter les transactions
'''

class TransactionConfiguration:

    def __init__(self):
        self.mq_queue = "transactions" #os.environ['MQ_QUEUE']
        self.mq_host = "dev2" #os.environ['MQ_HOST']

    def loadEnvironment(self):
        self.mq_queue = os.environ['MQ_QUEUE']
        self.mq_host = os.environ['MQ_HOST']

    @property
    def mqHost(self):
        return self.mq_host

    @property
    def mqQueue(self):
        return self.mq_queue


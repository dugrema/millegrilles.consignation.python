''' Executer thread lecture messages (test)
'''

from millegrilles.transaction.Configuration import TransactionConfiguration
from millegrilles.transaction.MessageDAO import PikaDAO, BaseCallback

''' Classe d'exemple pour implementation callback avec ACK (superclasse) '''
class CallbackImpl(BaseCallback):

    def callbackNouvelleTransaction(self, ch, method, properties, body):
        print("Message recu: %s" % body)
        super().callbackNouvelleTransaction(ch, method, properties, body)

class TransactionMain:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.transactionLirePika = PikaDAO(self.configuration)
        self.callbackImpl = CallbackImpl()

    def connecter(self):
        self.connexionMq = self.transactionLirePika.connecter()
        self.transactionLirePika.preparerQueueNouvellesTransactions(self.callbackImpl.callbackNouvelleTransaction)

    def deconnecter(self):
        self.transactionLirePika.deconnecter()

    # Methode principale de traitement
    def run(self):
        print("Demarrage du traitement des transactions MQ -> MongoDB")
        print("MQ Host: %s, MQ Queue: %s" % (self.configuration.mqHost, self.configuration.mqQueueNouvellesTransactions))

        self.connecter()

        print("Fin execution transactions MQ -> MongoDB")

# Fonction main. Demarre la lecture des queues de
# transaction et la sauvegarde dans MongoDB.
if __name__ == "__main__":
    transactionMain = TransactionMain()
    try:
        transactionMain.run()
    finally:
        transactionMain.deconnecter()

    exit(0)

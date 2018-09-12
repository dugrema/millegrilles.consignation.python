''' Executer thread lecture messages (test)
'''

from millegrilles.transaction.Configuration import TransactionConfiguration
from millegrilles.transaction.MessageDAO import PikaDAO, BaseCallback, JSONHelper

''' Classe d'exemple pour implementation callback avec ACK (superclasse) '''
class CallbackNouvelleTransaction(BaseCallback):

    def __init__(self):
        super().__init__()

        self.json_helper = JSONHelper()

    def callbackAvecAck(self, ch, method, properties, body):

        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        print("Message recu: %s" % message_dict)
        super().callbackAvecAck(ch, method, properties, body)

class TransactionMain:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.transactionLirePika = PikaDAO(self.configuration)
        self.callbackImpl = CallbackNouvelleTransaction()

    def connecter(self):
        self.connexionMq = self.transactionLirePika.connecter()
        self.transactionLirePika.demarrer_lecture_nouvelles_transactions(self.callbackImpl.callbackAvecAck)

    def deconnecter(self):
        self.transactionLirePika.deconnecter()

    # Methode principale de traitement
    def run(self):
        print("Demarrage du traitement des transactions MQ -> MongoDB")
        print("MQ Host: %s, MQ Queue: %s" % (self.configuration.mq_host, self.configuration.queue_nouvelles_transactions))

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

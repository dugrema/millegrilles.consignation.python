#!/usr/bin/python3

''' Programme principal pour transferer les nouvelles transactions vers MongoDB '''
from millegrilles.transaction.MessageDAO import PikaDAO, JSONHelper, BaseCallback
from millegrilles.transaction.DocumentDAO import MongoDAO
from millegrilles.transaction.Configuration import TransactionConfiguration

class ConsignateurTransaction(BaseCallback):

    def __init__(self):
        super().__init__()

        self.json_helper = JSONHelper()
        self.configuration = TransactionConfiguration()
        self.message_dao = PikaDAO(self.configuration)
        self.document_dao = MongoDAO(self.configuration)

    # Initialise les DAOs, connecte aux serveurs.
    def configurer(self):
        self.document_dao.connecter()
        self.message_dao.connecter()

    def executer(self):
        # Note: la methode demarrer_... est blocking
        self.message_dao.demarrer_lecture_nouvelles_transactions(self.callbackAvecAck)

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def callbackAvecAck(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        self.document_dao.sauvegarder_nouvelle_transaction(message_dict)
        super().callbackAvecAck(ch, method, properties, body)


def main():
    consignateur = ConsignateurTransaction()
    consignateur.configurer()
    consignateur.executer()

if __name__=="__main__":
    main()

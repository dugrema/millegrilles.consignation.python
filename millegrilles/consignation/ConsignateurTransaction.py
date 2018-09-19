#!/usr/bin/python3

''' Programme principal pour transferer les nouvelles transactions vers MongoDB '''
from millegrilles.dao.MessageDAO import PikaDAO, JSONHelper, BaseCallback
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles import Constantes
import signal

class ConsignateurTransaction(BaseCallback):

    def __init__(self):
        super().__init__()

        self.json_helper = JSONHelper()
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()
        self.message_dao = PikaDAO(self.configuration)
        self.document_dao = MongoDAO(self.configuration)

    # Initialise les DAOs, connecte aux serveurs.
    def configurer(self):
        self.document_dao.connecter()
        self.message_dao.connecter()

        # Executer la configuration pour RabbitMQ
        self.message_dao.configurer_rabbitmq()

        print("Configuration et connection completee")

    def executer(self):
        # Note: la methode demarrer_... est blocking
        self.message_dao.demarrer_lecture_nouvelles_transactions(self.callbackAvecAck)

    def deconnecter(self):
        self.document_dao.deconnecter()
        self.message_dao.deconnecter()
        print("Deconnexion completee")

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def callbackAvecAck(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        id_document = self.document_dao.sauvegarder_nouvelle_transaction(message_dict)
        uuid_transaction = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        self.message_dao.transmettre_evenement_persistance(id_document, uuid_transaction)
        super().callbackAvecAck(ch, method, properties, body)


consignateur = ConsignateurTransaction()

def exit_gracefully(signum, frame):
    print("Arret de OrienteurTransaction")
    consignateur.deconnecter()

def main():

    print("Demarrage de ConsignateurTransaction")

    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    consignateur.configurer()

    try:
        print("ConsignateurTransaction est pret")
        consignateur.executer()
    finally:
        print("Arret de ConsignateurTransaction")
        consignateur.deconnecter()

    print("ConsignateurTransaction est arrete")

if __name__=="__main__":
    main()

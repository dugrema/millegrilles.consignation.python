''' Script de test pour transmettre message de processus pour une transaction de lecture de senseur passifs

'''

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.processus.MGProcessus import MGPProcessusDemarreur
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles import Constantes

def message_test():

    message_test = {
        Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: "5bee12bce09409b7881c0da4"
    }

    processus = "mgdomaines_appareils_SenseursPassifs:ProcessusTransactionSenseursPassifsLecture"
    demarreur.demarrer_processus(processus, message_test)

    return message_test

# --- MAIN ---

configuration=TransactionConfiguration()
configuration.loadEnvironment()
print("Connecter Pika")
messageDao=PikaDAO(configuration)
messageDao.connecter()
print("Connection MongDB")
documentDao=MongoDAO(configuration)
documentDao.connecter()

print("Envoyer message")
demarreur=MGPProcessusDemarreur(messageDao, documentDao)

# TEST

enveloppe = message_test()

# FIN TEST

print("Sent: %s" % enveloppe)

messageDao.deconnecter()
documentDao.deconnecter()
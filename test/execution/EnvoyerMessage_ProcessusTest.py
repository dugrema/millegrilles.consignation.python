''' Script de test pour transmettre message de processus (test)

'''

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.processus.MGProcessus import MGPProcessusDemarreur
from millegrilles.dao.DocumentDAO import MongoDAO

def message_test():

    message_test_orienteur = {
        "libelle-transaction": "MGPProcessus.ProcessusTest.TestOrienteur"
    }

    demarreur.demarrer_processus("millegrilles_processus_ProcessusTest:TestOrienteur", message_test_orienteur)
#    demarreur.demarrer_processus("millegrilles_processus_ProcessusTest:TestInexistant", message_test_orienteur)

    return message_test_orienteur

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
''' Script de test pour transmettre message de transaction

'''

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO

#credentials = pika.PlainCredentials('mathieu', 'p1234')
#connection = pika.BlockingConnection(pika.ConnectionParameters('cuisine', 5674, credentials=credentials))

#queuename = "mg.sansnom.nouvelles_transactions"

#connection = pika.BlockingConnection( pika.ConnectionParameters('dev2', 5672) )
#channel = connection.channel()
#channel.queue_declare(queue=queuename)


def envoyer_message_test_senseur_lecture():

    lecture_modele = {
        'millivolt': 2811,
        'version': 6,
        'temps_lecture': 1537472850,
        'humidite': 55.9,
        'location': '15',
        'pression': 101.5,
        'senseur': 15,
        'noeud': 'test',
        'temperature': 19.00
    }

    enveloppe = messageDao.transmettre_message_transaction(lecture_modele,
                                                           'MGPProcessus.Appareils.ProcessusSenseurConserverLecture')

    return enveloppe

def message_test():

    message_test_orienteur = {
        "libelle-transaction": "MGPProcessus.ProcessusTest.TestOrienteur"
    }

    enveloppe = messageDao.transmettre_message_transaction(message_test_orienteur,
                                                           'MGPProcessus.ProcessusTest.TestOrienteur')

    return enveloppe

# --- MAIN ---

configuration = TransactionConfiguration()
configuration.loadEnvironment()
messageDao = PikaDAO(configuration)

messageDao.connecter()

# TEST

enveloppe = envoyer_message_test_senseur_lecture()

# FIN TEST

print("Sent: %s" % enveloppe)

messageDao.deconnecter()
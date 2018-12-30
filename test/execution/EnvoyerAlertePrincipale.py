# Script de test pour transmettre message de transaction

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

import datetime


def envoyer_message_test_alerte():

    alerte = {
        'message': "Alerte 7",
        'ts': int(datetime.datetime.utcnow().timestamp() * 1000)
    }

    enveloppe_val = generateur.soumettre_transaction(alerte, 'millegrilles.domaines.Principale.creerAlerte')

    return enveloppe_val


# --- MAIN ---
configuration = TransactionConfiguration()
configuration.loadEnvironment()
message_dao = PikaDAO(configuration)

message_dao.connecter()
message_dao.configurer_rabbitmq()

generateur = GenerateurTransaction(configuration, message_dao)

# TEST

enveloppe = envoyer_message_test_alerte()

# FIN TEST

print("Sent: %s" % enveloppe)

message_dao.deconnecter()

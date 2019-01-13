# Script de test pour transmettre message de transaction

import datetime

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction


def envoyer_message_test_senseur_lecture():

    lecture_modele = {
        'millivolt': 2911,
        'version': 6,
        'temps_lecture': int(datetime.datetime.utcnow().timestamp()),
        'humidite': 54.8,
        'location': 'CUISINE',
        'pression': 101.6,
        'senseur': 16,
        'noeud': 'test',
        'temperature': 21.60
    }

    enveloppe_val = generateur.soumettre_transaction(lecture_modele, 'millegrilles.domaines.SenseursPassifs.lecture')

    return enveloppe_val


# --- MAIN ---
configuration = TransactionConfiguration()
configuration.loadEnvironment()
message_dao = PikaDAO(configuration)

message_dao.connecter()
message_dao.configurer_rabbitmq()

generateur = GenerateurTransaction(configuration, message_dao)

# TEST

enveloppe = envoyer_message_test_senseur_lecture()

# FIN TEST

print("Sent: %s" % enveloppe)

message_dao.deconnecter()

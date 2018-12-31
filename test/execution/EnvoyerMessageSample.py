# Script de test pour transmettre message de transaction

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction


def envoyer_message_test_senseur_lecture():

    lecture_modele = {
        'millivolt': 2911,
        'version': 6,
        'temps_lecture': 1537504060,
        'humidite': 54.9,
        'location': 'NA',
        'pression': 101.5,
        'senseur': 16,
        'noeud': 'test',
        'temperature': 21.00
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

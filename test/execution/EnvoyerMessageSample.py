# Script de test pour transmettre message de transaction

import datetime

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction


def envoyer_message_test_senseur_lecture():

    lecture_modele = {
        'millivolt': 2878,
        'version': 6,
        'temps_lecture': int(datetime.datetime.utcnow().timestamp()),
#        'humidite': 54.8,
        'location': 'CUISINE',
#        'pression': 101.6,
        'senseur': 17,
        'noeud': 'test',
        'temperature': 8.0
    }

    enveloppe_val = generateur.soumettre_transaction(lecture_modele, 'millegrilles.domaines.SenseursPassifs.lecture')

    return enveloppe_val


# --- MAIN ---
contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser(init_document=False)

generateur = GenerateurTransaction(contexte)

# TEST

enveloppe = envoyer_message_test_senseur_lecture()

# FIN TEST

print("Sent: %s" % enveloppe)

contexte.message_dao.deconnecter()

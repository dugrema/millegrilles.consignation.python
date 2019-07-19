# Script de test pour transmettre message de transaction

import datetime

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction


def envoyer_message_test_senseur_lecture():

    lecture_modele = {
        'millivolt': 2875,
        'version': 6,
        'temps_lecture': int(datetime.datetime.utcnow().timestamp()),
        'humidite': 89.1,
        'location': 'Cuisine bonA',
        'pression': 101.3,
        'senseur': 15,
        'noeud': 'test',
        'temperature': 22.7
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

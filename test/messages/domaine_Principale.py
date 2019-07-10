# Script de test pour transmettre message de transaction

import datetime

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction


class MessagesSample:

    def __init__(self):
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser(init_document=False)
        self.generateur = GenerateurTransaction(self.contexte)

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def envoyer_message_test_senseur_lecture(self):

        lecture_modele = {
            'millivolt': 2878,
            'version': 6,
            'temps_lecture': int(datetime.datetime.utcnow().timestamp()),
            # 'humidite': 54.8,
            'location': 'CUISINE',
            # 'pression': 101.6,
            'senseur': 17,
            'noeud': 'test',
            'temperature': 8.0
        }

        enveloppe_val = self.generateur.soumettre_transaction(lecture_modele, 'millegrilles.domaines.SenseursPassifs.lecture')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val


# --- MAIN ---
sample = MessagesSample()

# TEST
enveloppe = sample.envoyer_message_test_senseur_lecture()

# FIN TEST
sample.deconnecter()

# Script de test pour transmettre une requete MongoDB

from millegrilles import Constantes
from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

import time
from threading import Thread


class TestEnvoyerRequete:

    def __init__(self, contexte):
        self.callback = TestCallback(contexte, self)
        self.generateur = GenerateurTransaction(contexte)

        self.reponse = None

    def envoyer_message_test_alerte(self):

        requete = {
            'requetes': [
                {
                    'type': 'mongodb',
                    "filtre": {
                        "_mg-libelle": "noeud.individuel",
                        "noeud": {
                            "$in": ["test"]
                        }
                    },
                    "projection": {
                        "noeud": 1,
                        "dict_senseurs": 1
                    }
                }
            ],
            'retour': {
                "routage": "reponse.%s" % message_dao.queue_reponse
            }
        }

        # enveloppe_val = generateur.soumettre_transaction(requete, 'millegrilles.domaines.Principale.creerAlerte')
        enveloppe_requete = self.generateur.preparer_enveloppe(requete, 'millegrilles.domaines.SenseursPassifs.requete')
        self.generateur.transmettre_requete(enveloppe_requete, 'requete.millegrilles.domaines.SenseursPassifs.mongodb', Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS)

        return enveloppe_requete


class TestCallback(BaseCallback):

    def __init__(self, contexte, classe_requete):
        super().__init__(contexte)
        self.classe_requete = classe_requete

    def traiter_message(self, ch, method, properties, body):
        print("Reponse recue: %s" % body)
        self.reponse = body


# --- MAIN ---

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser(init_document=False)

test = TestEnvoyerRequete(contexte)
message_dao = contexte.message_dao
message_dao.inscrire_topic(Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS, [], test.callback.callbackAvecAck)

# TEST

enveloppe = test.envoyer_message_test_alerte()

print("Sent: %s" % enveloppe)
# message_dao.channel.consume(message_dao.queue_reponse)
thread_consume = Thread(target=message_dao.start_consuming)
thread_consume.start()
time.sleep(10)
message_dao.channel.stop_consuming()

# FIN TEST



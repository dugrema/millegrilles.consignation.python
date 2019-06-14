# Script de test pour transmettre message de transaction

from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

import time


class Reception:

    def __init__(self):
        pass

    def recevoir_message(self, ch, method, properties, body):
        print("Message recu: %s\n%s" % (method.routing_key, body))
        ch.basic_ack(delivery_tag=method.delivery_tag)


# --- MAIN ---

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser(init_document=False)
message_dao = contexte.message_dao

reception = Reception()

# TEST

message_dao.inscrire_topic('millegrilles.middleware', ['transaction.nouvelle', 'topic.test'], reception.recevoir_message)
# message_dao.enregistrer_callback(queue='nouvelles_transactions', callback=reception.recevoir_message)

# time.sleep(30)
message_dao.start_consuming()

# FIN TEST

message_dao.deconnecter()

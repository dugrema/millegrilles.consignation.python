# Script de test pour transmettre une requete MongoDB

from millegrilles import Constantes
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

import datetime
from threading import Thread


# class TestCallback(BaseCallback):
#
#     def __init__(self, contexte, classe_requete):
#         super().__init__(contexte)
#         self.classe_requete = classe_requete
#
#     def traiter_message(self, ch, method, properties, body):
#         print("Reponse recue: %s" % body)
#         self.reponse = body


class ModifierDateTransaction:

    def __init__(self, contexte, offset: datetime.timedelta, domaines: list = None):
        # self.callback = TestCallback(contexte, self)
        self.__contexte = contexte
        self.__domaines = domaines or ['MaitreDesCles']
        self.__offset = offset

    def appliquer(self):
        for domaine in self.__domaines:
            self.traiter_transaction(domaine)

    def traiter_transaction(self, domaine):
        collection = self.__contexte.document_dao.get_collection(domaine)
        print("Collection chargee")

        filtre = {
            '_evenements.transaction_complete': True
        }
        curseur = collection.find(filtre)

        for doc in curseur:
            filtre = {'_id': doc['_id']}
            date_transaction = doc['_evenements']['signature_verifiee']
            nouvelle_date = date_transaction + self.__offset
            set_ops = {
                '_evenements.backup_flag': False,
                '_evenements.transaction_traitee': nouvelle_date,
            }
            ops = {
                '$set': set_ops,
                '$unset': {'_evenements.backup_horaire': True}
            }
            collection.update_one(filtre, ops)


def reset_dates_moins2heures(contexte):
    offset = datetime.timedelta(hours=-2)
    modificateur = ModifierDateTransaction(contexte, offset)
    modificateur.appliquer()


def reset_dates_moins1semaine(contexte):
    offset = datetime.timedelta(days=-7)
    modificateur = ModifierDateTransaction(contexte, offset)
    modificateur.appliquer()


def reset_dates_moins2ans(contexte):
    offset = datetime.timedelta(days=-720)
    modificateur = ModifierDateTransaction(contexte, offset)
    modificateur.appliquer()

# --- MAIN ---

def main():
    contexte = ContexteRessourcesDocumentsMilleGrilles()
    contexte.initialiser(init_document=True)

    # reset_dates_moins2heures(contexte)
    reset_dates_moins1semaine(contexte)
    # reset_dates_moins2ans(contexte)


# TEST
if __name__ == '__main__':
    main()


# test = TestEnvoyerRequete(contexte)
# message_dao = contexte.message_dao
# message_dao.inscrire_topic(Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS, [], test.callback.callbackAvecAck)
#
# enveloppe = test.envoyer_message_test_alerte()
#
# print("Sent: %s" % enveloppe)
# # message_dao.channel.consume(message_dao.queue_reponse)
# thread_consume = Thread(target=message_dao.start_consuming)
# thread_consume.start()
# time.sleep(10)
# message_dao.channel.stop_consuming()

# FIN TEST



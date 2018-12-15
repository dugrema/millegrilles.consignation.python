from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.domaines.Notifications import NotificationsConstantes
from millegrilles import Constantes
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

import datetime


class NotificationActionExempleTest:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()

        self.message_dao = PikaDAO(self.configuration)
        self.message_dao.connecter()

        self.generateur_transaction = GenerateurTransaction(self.configuration, self.message_dao)

    def deconnecter(self):
        self.message_dao.deconnecter()

    def test1(self):

        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)
        domaine = NotificationsConstantes.TRANSACTION_ACTION_NOTIFICATION

        transaction_message = dict({
            NotificationsConstantes.LIBELLE_ID_NOTIFICATION: '5c15217ce094095d8c8d314b',
            NotificationsConstantes.LIBELLE_ACTION: NotificationsConstantes.ACTION_RAPPEL,
            NotificationsConstantes.LIBELLE_DATE_ATTENTE_ACTION: 180
        })

        self.generateur_transaction.soumettre_transaction(transaction_message, domaine)

        print("Sent notification domaine %s: %s" % (domaine, transaction_message))


test = NotificationActionExempleTest()

try:
    # TEST
    print("Envoyer notification")
    test.test1()
finally:
    test.deconnecter()

# FIN TEST


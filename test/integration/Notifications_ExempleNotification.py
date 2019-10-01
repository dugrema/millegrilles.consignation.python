from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.domaines.Taches import TachesConstantes
from millegrilles import Constantes

import datetime


class NotificationExempleTest:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()

        self.message_dao = PikaDAO(self.configuration)
        self.message_dao.connecter()

    def deconnecter(self):
        self.message_dao.deconnecter()

    def test1(self):

        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)
        notification = dict({
            '_mg-libelle': 'regle_simple',
            'evenements': Constantes.EVENEMENT_NOTIFICATION,
            'source': {
                '_collection': 'mgdomaines_appareils_SenseursPassifs',
                '_id': "5bef31be82cc2cb5ab0d57fe"
            },
            'regles': [
                {"pasbonne_10": {
                    "element": "temperature"
                }}
            ],
            "date": int(datetime.datetime.utcnow().timestamp()),
            'valeurs': {
                "element": "temperature",
                "valeur": 24.6
            }
        })

        self.message_dao.transmettre_notification(notification, TachesConstantes.AVERTISSEMENT)

        print("Sent notification: %s" % notification)


test = NotificationExempleTest()

try:
    # TEST
    print("Envoyer notification")
    test.test1()
finally:
    test.deconnecter()

# FIN TEST


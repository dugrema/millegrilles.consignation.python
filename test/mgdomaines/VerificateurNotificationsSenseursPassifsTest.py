from millegrilles.domaines.SenseursPassifs import VerificateurNotificationsSenseursPassifs
import logging
import json

DOC_SAMPLE1 = {
    '_id': 'DOC_SAMPLE1',
    'valeur1': 12.8,
    'valeur2': -1
}

REGLES_sample1 = [
    {
        'avertissement_hors_intervalle': {
            'element': 'valeur1',
            'min': 5,
            'max': 10
        }
    },
    {
        'avertissement_inferieur': {
            'element': 'valeur2',
            'min': 0
        }
    }
]


class MessageDAOStub:

    def __init__(self):
        self._logger = logging.getLogger('test')

    def transmettre_notification(self, notification_formattee, niveau):
        notif_pp = json.dumps(notification_formattee, sort_keys=True, indent=2)
        self._logger.info("Notification niveau %s: %s" % (niveau, notif_pp))


class VerificateurTest:

    def __init__(self, message_dao, regles, doc_senseur):
        self.verificateur = VerificateurNotificationsSenseursPassifs(message_dao, regles, doc_senseur)
        self._logger = logging.getLogger('test')

    def test(self):
        self.verificateur.traiter_regles()


def test():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('test').setLevel(logging.DEBUG)
    message_dao = MessageDAOStub()

    verificateur = VerificateurTest(message_dao, REGLES_sample1, DOC_SAMPLE1)
    verificateur.test()


test()
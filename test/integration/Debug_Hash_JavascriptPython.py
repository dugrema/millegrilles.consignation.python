from millegrilles.util.BaseSendMessage import BaseEnvoyerMessageEcouter
import logging


class TestHashMessage(BaseEnvoyerMessageEcouter):

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger('%s' % self.__class__.__name__)

    def hasher_message(self, message):
        enveloppe = self.generateur.preparer_enveloppe(message, domaine='domaine.test')
        return enveloppe

    def executer(self):
        message1 = {
            'texte': 'àé La cabane à sucre, c''est génial.'
        }
        enveloppe1 = self.hasher_message(message1)
        self.logger.debug(enveloppe1)
        self.logger.debug(enveloppe1['en-tete']['hachage-contenu'])
        del enveloppe1['_signature']
        del enveloppe1['en-tete']
        self.logger.debug(enveloppe1)

        message2 = {
            'texte': 'Pas de carateres speciaux, juste du anglais.',
        }
        enveloppe2 = self.hasher_message(message2)
        self.logger.debug(enveloppe2)
        self.logger.debug(enveloppe2['en-tete']['hachage-contenu'])
        del enveloppe2['_signature']
        del enveloppe2['en-tete']
        self.logger.debug(enveloppe2)

        self.deconnecter()

# ---- TEST -----
testMessage = TestHashMessage()
logging.basicConfig(level=logging.WARN)
logging.getLogger('TestHashMessage').setLevel(logging.DEBUG)
testMessage.executer()

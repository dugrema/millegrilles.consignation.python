import logging

from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.Configuration import TransactionConfiguration

logger = logging.getLogger(__name__)


class CeduleurMessageTest:

    def __init__(self):
        self.configuration = TransactionConfiguration()
        self.configuration.loadEnvironment()

        self.message_dao = PikaDAO(self.configuration)
        self.message_dao.connecter()

    def deconnecter(self):
        self.message_dao.deconnecter()

    def transmettre_evenement_ceduleur(self):
        self.message_dao.transmettre_evenement_ceduleur()


# --- MAIN ---
logger.setLevel(logging.DEBUG)
logging.getLogger('mgdomaines').setLevel(logging.INFO)

test = CeduleurMessageTest()
try:
    test.transmettre_evenement_ceduleur()
except Exception:
    logger.exception("Erreur test")
finally:
    test.deconnecter()

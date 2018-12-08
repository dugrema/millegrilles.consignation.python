import logging
import time
import datetime
import signal

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

    def temps_restant_pourminute(self):
        # Note: on utilise 62 pour ajouter executer 2 secondes apres la minute
        time_sleep = 62 - (time.time()%60)
        return time_sleep


# --- MAIN ---
logging.basicConfig(level=logging.WARNING, format="%(relativeCreated)6d %(threadName)s %(message)s")
logger.setLevel(logging.DEBUG)
logging.getLogger('mgdomaines').setLevel(logging.INFO)
test = CeduleurMessageTest()


def exit_gracefully(self):
    test.deconnecter()


signal.signal(signal.SIGINT, exit_gracefully)
signal.signal(signal.SIGTERM, exit_gracefully)

try:
    while True:
        # Verifier avant d'executer, s'il reste moins de 30 secondes on attend la prochaine minute
        temps_restant = test.temps_restant_pourminute()

        if temps_restant > 30:
            test.transmettre_evenement_ceduleur()
            temps_restant = test.temps_restant_pourminute()  # Recalculer apres transmission message
            logger.debug("Temps restant: %d. Heure: %s" % (temps_restant, str(datetime.datetime.now())))
        else:
            logger.warning("On skip, il reste juste %d secondes d'attente" % temps_restant)

        time.sleep(temps_restant)

except Exception:
    logger.exception("Erreur test")
finally:
    test.deconnecter()

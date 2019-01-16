import logging
# import time
# import datetime
# import signal
# import argparse
import pytz
import datetime

from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
from millegrilles.util.Ceduleur import CeduleurMilleGrilles

logger = logging.getLogger(__name__)


class CeduleurMessageTest:

    def __init__(self):
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser(init_message=True)

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def transmettre_evenement_ceduleur(self):

        timestamp_utc = datetime.datetime.now(tz=pytz.UTC)
        ts_dict = {
            'UTC': timestamp_utc.timetuple(),
            'joursemaine': timestamp_utc.weekday()
        }

        # Faire la liste des timezones a inclure. La routing key va utiliser la version courte de la timezone.
        timezones = [
            pytz.UTC,
        ]

        indicateurs = ['heure']
        nom_timezones = []
        for tz in timezones:
            local_tz_name = str(tz)
            nom_timezones.append(local_tz_name)

        ts_dict['timezones'] = nom_timezones

        self.contexte.message_dao.transmettre_evenement_ceduleur(ts_dict, indicateurs)


# --- MAIN ---
#ceduleur = CeduleurMilleGrilles()
#ceduleur.main()

logging.basicConfig(level=logging.WARNING, format="%(relativeCreated)6d %(threadName)s %(message)s")
logger.setLevel(logging.DEBUG)
logging.getLogger('mgdomaines').setLevel(logging.INFO)
test = CeduleurMessageTest()
test.transmettre_evenement_ceduleur()

# def exit_gracefully(self):
#     test.deconnecter()
#
#
# signal.signal(signal.SIGINT, exit_gracefully)
# signal.signal(signal.SIGTERM, exit_gracefully)
#
# try:
#     while True:
#         # Verifier avant d'executer, s'il reste moins de 30 secondes on attend la prochaine minute
#         temps_restant = test.temps_restant_pourminute()
#
#         if temps_restant > 30:
#             test.transmettre_evenement_ceduleur()
#             temps_restant = test.temps_restant_pourminute()  # Recalculer apres transmission message
#             logger.debug("Temps restant: %d. Heure: %s" % (temps_restant, str(datetime.datetime.now())))
#         else:
#             logger.warning("On skip, il reste juste %d secondes d'attente" % temps_restant)
#
#         time.sleep(temps_restant)
#
# except Exception:
#     logger.exception("Erreur test")
# finally:
#     test.deconnecter()

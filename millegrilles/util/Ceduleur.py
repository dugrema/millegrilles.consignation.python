# Module pour le ceduleur MilleGrilles
# Le ceduleur envoit un message a toutes les minutes. Voir methode MessageDAO.PikaDAO.transmettre_evenement_ceduleur.
import time
import datetime
import pytz
import logging
import threading

from threading import Event, Thread
from pika.exceptions import ConnectionClosed, ChannelClosed

from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration


class CeduleurMilleGrilles(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self._stop_event = Event()
        self._stop_event.set()
        self.__channel = None

        self.logger = logging.getLogger('%s.CeduleurMilleGrilles' % __name__)

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel

        self.contexte.message_dao.configurer_rabbitmq()
        # self.contexte.message_dao.demarrer_lecture_nouvelles_transactions(self.message_handler.callbackAvecAck)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def is_channel_open(self):
        return self.__channel is not None

    def configurer_parser(self):
        super().configurer_parser()

        # self.parser.add_argument(
        #     '--debug', action="store_true", required=False,
        #     help="Active le debugging (logger)"
        # )

        self.parser.add_argument(
            '--test_indicateurs', action="store_true", required=False,
            help="Transmet tous les indicateurs a toutes les minutes (pour tester logique)"
        )

    def transmettre_evenement_ceduleur(self):

        timestamp_utc = datetime.datetime.now(tz=pytz.UTC)
        ts_dict = {
            'UTC': timestamp_utc.timetuple(),
            'joursemaine': timestamp_utc.weekday()
        }

        # Faire la liste des timezones a inclure. La routing key va utiliser la version courte de la timezone.
        timezones = [
            pytz.UTC,
            pytz.timezone("Canada/Eastern")
        ]

        indicateurs = []
        if timestamp_utc.minute == 0:
            indicateurs.append('heure')

        nom_timezones = []
        for tz in timezones:
            timestamp_tz = timestamp_utc.astimezone(tz=tz)
            local_tz_name = str(tz)
            nom_timezones.append(local_tz_name)

            indicateurs_tz = self.get_indicateurs(timestamp_tz)
            if len(indicateurs_tz) > 0:
                indicateurs.append(local_tz_name)
            indicateurs.extend(indicateurs_tz)

        ts_dict['timezones'] = nom_timezones

        self.contexte.message_dao.transmettre_evenement_ceduleur(ts_dict, indicateurs)

    def get_indicateurs(self, timestamp):

        indicateurs = []
        if not self.args.test_indicateurs:
            # Calculer quels indicateurs on doit inclure
            if timestamp.minute == 0:
                if timestamp.hour == 0:
                    indicateurs.append('jour')
                    if timestamp.day == 1:
                        indicateurs.append('mois')
                        if timestamp.month == 1:
                            indicateurs.append('annee')
                    if timestamp.weekday() == 0:
                        indicateurs.append('semaine')
        else:
            indicateurs = ['heure', 'jour', 'mois', 'annee', 'semaine']

        return indicateurs

    @staticmethod
    def temps_restant_pourminute():
        # Note: on utilise 62 pour ajouter executer 2 secondes apres la minute
        time_sleep = 62 - (time.time() % 60)
        return time_sleep

    def exit_gracefully(self, signal=None, frame=None):
        self._stop_event.set()
        super().exit_gracefully()

    def executer(self):

        self._stop_event.clear()  # Pret a l'execution

        # Preparer configuration / logging
        if self.args.debug:
            self.logger.setLevel(logging.DEBUG)
            logging.getLogger('millegrilles').setLevel(logging.INFO)  # Mettre le reste du domaine a INFO

        while not self._stop_event.is_set():
            try:
                # Verifier avant d'executer, s'il reste moins de 30 secondes on attend la prochaine minute
                temps_restant = CeduleurMilleGrilles.temps_restant_pourminute()

                if temps_restant > 45:
                    self.transmettre_evenement_ceduleur()

                    # Recalculer apres transmission message
                    temps_restant = CeduleurMilleGrilles.temps_restant_pourminute()

                    self.logger.debug("Temps restant: %d. Heure: %s" % (temps_restant, str(datetime.datetime.now())))

                else:
                    self.logger.warning("On skip, il reste juste %d secondes d'attente" % temps_restant)

                self._stop_event.wait(temps_restant)

            except ChannelClosed as ce:
                self.logger.fatal("Connection a Pika fermee, on termine l'execution. %s" % str(ce))
                self.exit_gracefully()  # Connection perdue, On va fermer l'application

            except ConnectionClosed as ce:
                self.logger.fatal("Connection a Pika fermee, on termine l'execution. %s" % str(ce))
                self.exit_gracefully()  # Connection perdue, On va fermer l'application

            except Exception as e:
                self.logger.exception("Erreur durant le cycle de ceduleur: %s" % str(e))

                # On attend 30 secondes pour tenter a nouveau sauf si l'erreur vient de l'arret de l'application
                self._stop_event.wait(30)

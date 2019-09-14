#!/usr/bin/python3

# Module qui permet de demarrer les appareils sur un Raspberry Pi
import traceback
import argparse
import logging
import time

from threading import Event, Thread

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import ExceptionConnectionFermee
from millegrilles.domaines.SenseursPassifs import ProducteurTransactionSenseursPassifs
from millegrilles import Constantes

from millegrilles.util.Daemon import Daemon


class DemarreurNoeud(Daemon):

    def __init__(
            self,
            pidfile='/run/mg-noeud.pid',
            stdin='/dev/null',
            stdout='/var/log/mg-noeud.log',
            stderr='/var/log/mg-noeud.err'
    ):
        # Call superclass init
        Daemon.__init__(self, pidfile, stdin, stdout, stderr)

        logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.DEBUG)
        logging.getLogger().setLevel(logging.WARNING)
        logging.getLogger('millegrilles.noeuds').setLevel(logging.INFO)

        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._logger.info("\n-----------\n\n-----------")
        self._logger.info("Demarrage de %s en cours\n-----------" % self.__class__.__name__)

        self._parser = argparse.ArgumentParser(description="Demarrer un noeud MilleGrilles")
        self._args = None

        self._intervalle_entretien = None
        self._max_backlog = None
        self._apcupsd = None
        self._dummysenseurs = None

        self._contexte = ContexteRessourcesMilleGrilles()
        self._producteur_transaction = None
        self.__thread_mq_ioloop = None

        self._chargement_reussi = False  # Vrai si au moins un module a ete charge
        self._stop_event = Event()
        self._stop_event.set()  # Set initiale, faire clear pour activer le processus

        self._backlog_messages = []  # Utilise pour stocker les message qui n'ont pas ete transmis

    def print_help(self):
        self._parser.print_help()

    def parse(self):
        self._parser.add_argument(
            'command', type=str, nargs=1, choices=['start', 'stop', 'restart'],
            help="Commande a executer: start, stop, restart"
        )
        self._parser.add_argument(
            '--apcupsd', type=int, nargs=1, required=False,
            help="Active le module pour les UPS APC avec numero de senseur en parametre."
        )
        self._parser.add_argument(
            '--apcupsd_host', type=str, nargs=1, required=False,
            help="Host ou se trouver le serveur du UPS APC (apcupsd)."
        )
        self._parser.add_argument(
            '--apcupsd_port', type=int, nargs=1, required=False,
            help="Port du serveur UPS APC (apcupsd)."
        )
        self._parser.add_argument(
            '--apcupsd_pipe', type=str, nargs=1, required=False,
            help="Path pour le pipe d'evenements pour les scripts apcupsd."
        )
        self._parser.add_argument(
            '--maint', type=int, nargs=1, default=60,
            required=False, help="Change le nombre de secondes entre les verifications de connexions"
        )
        self._parser.add_argument(
            '--backlog', type=int, nargs=1, default=1000,
            required=False, help="Change le nombre messages maximum qui peuvent etre conserves dans le backlog"
        )
        self._parser.add_argument(
            '--noconnect', action="store_true", required=False,
            help="Effectue la connexion aux serveurs plus tard plutot qu'au demarrage."
        )
        self._parser.add_argument(
            '--dummysenseurs', action="store_true", required=False,
            help="Initalise un emetteur de lecture dummy, pour tester la connexion"
        )
        self._parser.add_argument(
            '--debug', action="store_true", required=False,
            help="Active le logging maximal"
        )
        self._args = self._parser.parse_args()

    def executer_daemon_command(self):
        
        if self._args.debug:
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
        
        daemon_command = self._args.command[0]
        if daemon_command == 'start':
            self.start()
        elif daemon_command == 'stop':
            self.stop()
        elif daemon_command == 'restart':
            self.restart()

    def start(self):
        Daemon.start(self)

    def stop(self):
        Daemon.stop(self)

    def restart(self):
        Daemon.restart(self)

    def run(self):
        self._logger.info("Demarrage Daemon")
        self.setup_modules()

        if self._chargement_reussi:
            self._stop_event.clear()  # Permettre de bloquer sur le stop_event.

        while not self._stop_event.is_set():
            # Faire verifications de fonctionnement, watchdog, etc...
            try:
                self.traiter_backlog_messages()
            except Exception:
                self._logger.exception("Erreur traitement backlog de messages")

            # Sleep
            self._stop_event.wait(self._intervalle_entretien)
        self._logger.info("Fin execution Daemon")

    def setup_modules(self):
        # Charger la configuration et les DAOs
        self._logger.info("Setup modules")
        doit_connecter = not self._args.noconnect
        self._contexte.initialiser(init_document=False, connecter=doit_connecter)
        # self.__thread_mq_ioloop = Thread(name='MQ-ioloop', target=self._contexte.message_dao.run_ioloop)
        # self.__thread_mq_ioloop.start()

        self._producteur_transaction = ProducteurTransactionSenseursPassifs(self._contexte)

        # Verifier les parametres
        self._intervalle_entretien = self._args.maint
        self._max_backlog = self._args.backlog

        if self._args.apcupsd:
            try:
                self.inclure_apcupsd()
            except Exception as erreur_lcd:
                self._logger.exception("Erreur chargement apcupsd: %s" % str(erreur_lcd))
                traceback.print_exc()

        if self._args.dummysenseurs:
            self.inclure_dummysenseurs()

    def fermer(self):
        self._stop_event.set()

        try:
            self.contexte.message_dao.deconnecter()
            if self.contexte.document_dao is not None:
                self.contexte.document_dao.deconnecter()
        except Exception as edao:
            self._logger.info("Erreur deconnexion DAOs: %s" % str(edao))

        if self._apcupsd is not None:
            try:
                self._apcupsd.fermer()
            except Exception as enrf:
                self._logger.info("erreur fermeture apcupsd: %s" % str(enrf))

    def inclure_apcupsd(self):
        self._logger.info("Activer apcupsd via nis")
        from millegrilles.noeuds.Apcups import ApcupsdCollector
        no_senseur = self._args.apcupsd[0]
        config = {}
        if self._args.apcupsd_host:
            config['hostname'] = self._args.apcupsd_host[0]
        if self._args.apcupsd_port:
            config['port'] = self._args.apcupsd_port[0]
        if self._args.apcupsd_pipe:
            config['pipe_path'] = self._args.apcupsd_pipe[0]
        self._logger.info("Configuration apcupsd: %s" % config)
        self._apcupsd = ApcupsdCollector(no_senseur=no_senseur, config=config)
        self._apcupsd.start(self.transmettre_lecture_callback)
        self._chargement_reussi = True

    def inclure_dummysenseurs(self):
        self._logger.info("Activer dummysenseurs")
        self._dummysenseurs = DummySenseurs(no_senseur=1)
        self._dummysenseurs.start(self.transmettre_lecture_callback)
        self._chargement_reussi = True

    def transmettre_lecture_callback(self, dict_lecture):
        try:
            if not self.contexte.message_dao.in_error:
                self._producteur_transaction.transmettre_lecture_senseur(dict_lecture)
            else:
                self._logger.info("Message ajoute au backlog: %s" % str(dict_lecture))
                if len(self._backlog_messages) < 1000:
                    self._backlog_messages.append(dict_lecture)
                else:
                    self._logger.warning("Backlog > 1000, message perdu: %s" % str(dict_lecture))

        except ExceptionConnectionFermee as e:
            # Erreur, la connexion semble fermee. On va tenter une reconnexion
            self._backlog_messages.append(dict_lecture)
            self.contexte.message_dao.enter_error_state()

    ''' Verifie s'il y a un backlog, tente de reconnecter au message_dao et transmettre au besoin. '''
    def traiter_backlog_messages(self):
        if len(self._backlog_messages) > 0:
            # Tenter de reconnecter a RabbitMQ
            # if self.contexte.message_dao.in_error:
            #     try:
            #         self.contexte.message_dao.connecter()
            #     except:
            #         self._logger.exception("Erreur connexion MQ")

            # La seule facon de confirmer la connexion et d'envoyer un message
            # On tente de passer le backlog en remettant le message dans la liste en cas d'echec
            message = self._backlog_messages[0]  # Tenter transmettre un message, mais le garder en cas d'echec
            try:
                self._producteur_transaction.transmettre_lecture_senseur(message)
                # Succes (pas d'exception lancee), on enleve le premier message du backlog
                self._backlog_messages.pop()

                # Transmettre le reste des messages
                while len(self._backlog_messages) > 0:
                    message = self._backlog_messages.pop()
                    self._producteur_transaction.transmettre_lecture_senseur(message)
                self._logger.info("Traitement backlog complete")
            except Exception as e:
                self._logger.warning("Erreur traitement backlog, on push le message: %s" % str(e))
                self._backlog_messages.append(message)
                traceback.print_exc()

    @property
    def contexte(self):
        return self._contexte


# Thermometre AM2302 connecte sur une pin GPIO
# Dependances:
#   - Adafruit package Adafruit_DHT
class DummySenseurs:

    def __init__(self, no_senseur, intervalle_lectures=50):
        self._no_senseur = no_senseur
        self._intervalle_lectures = intervalle_lectures
        self._callback_soumettre = None
        self._stop_event = Event()
        self._thread = None

        self._stop_event.set()
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._valeurs = [
            {'humidite': 40, 'temperature': 17},
            {'humidite': 42, 'temperature': 16},
            {'humidite': 43, 'temperature': 15},
            {'humidite': 44, 'temperature': 14},
            {'humidite': 50, 'temperature': 13.5},
        ]

    def lire(self):
        lecture = self._valeurs[0]
        humidite = lecture['humidite']
        temperature = lecture['temperature']

        dict_message = {
            'version': 6,
            'senseur': self._no_senseur,
            'temps_lecture': int(time.time()),
            'temperature': round(temperature, 1),
            'humidite': round(humidite, 1)
        }

        self._callback_soumettre(dict_message)

    def start(self, callback_soumettre):
        self._callback_soumettre = callback_soumettre
        self._stop_event.clear()

        # Demarrer thread
        self._thread = Thread(target=self.run)
        self._thread.start()

    def fermer(self):
        self._stop_event.set()

    def run(self):
        while not self._stop_event.is_set():
            try:
                self.lire()
            except:
                self._logger.exception("DummySenseurs: Erreur lecture AM2302")
            finally:
                self._stop_event.wait(self._intervalle_lectures)


# **** MAIN ****
def main():
    try:
        demarreur.parse()
        demarreur.executer_daemon_command()
    except Exception as e:
        print("!!! ******************************")
        print("MAIN: Erreur %s" % str(e))
        traceback.print_exc()
        print("!!! ******************************")
        demarreur.print_help()


if __name__ == "__main__":
    demarreur = DemarreurNoeud()
    main()
